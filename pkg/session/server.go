// Package session binds the debug target to the serial protocol: capability
// negotiation, exclusive session ownership, command dispatch, asynchronous
// interrupt while running, and deterministic teardown on disconnect/timeout.
package session

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/clock"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/protocol"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

// Config configures a Server.
type Config struct {
	// StrictCaps rejects connections that do not negotiate a compatible set
	// instead of degrading.
	StrictCaps bool
	// IdleTimeout closes a session silent for that long. 0 disables.
	IdleTimeout time.Duration
	// Link configures frame retransmission.
	Link protocol.LinkOptions
	// Clock drives the idle timer (defaults to wall clock).
	Clock clock.Clock
	// Logger receives a line per frame, state transition and rejection.
	Logger Logger
}

// Logger is the minimal logging surface (testing.T implements a Printf-style
// logger through the TestLogger adapter).
type Logger interface {
	Printf(format string, args ...any)
}

type discardLogger struct{}

func (discardLogger) Printf(string, ...any) {}

// DefaultConfig returns permissive defaults.
func DefaultConfig() Config {
	return Config{
		IdleTimeout: 5 * time.Second,
		Link:        protocol.DefaultLinkOptions(),
		Clock:       clock.NewRealClock(),
		Logger:      discardLogger{},
	}
}

// Server owns one target and admits at most one active debug session at a time.
type Server struct {
	target *target.Target
	cfg    Config

	mu     sync.Mutex
	active bool
	closed bool
}

// New constructs a server for an already-loaded target.
func New(t *target.Target, cfg Config) *Server {
	if cfg.Clock == nil {
		cfg.Clock = clock.NewRealClock()
	}
	if cfg.Logger == nil {
		cfg.Logger = discardLogger{}
	}
	if cfg.Link.Clock == nil {
		cfg.Link.Clock = cfg.Clock
	}
	return &Server{target: t, cfg: cfg}
}

// Active reports whether a session currently owns the target.
func (s *Server) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Close terminates any active session and releases the server.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

// Sentinel errors.
var (
	ErrSessionBusy        = errors.New("session: target already has an active session")
	ErrCapabilityRejected = errors.New("session: capability negotiation failed")
	ErrIdleTimeout        = errors.New("session: idle timeout")
	ErrServerClosed       = errors.New("session: server closed")
)

// ServeConn runs the protocol over one transport until disconnect, fatal
// protocol error, idle timeout or detach. A concurrent second ServeConn is
// rejected immediately with ErrSessionBusy (the caller may still send one
// error frame itself; ServeConn does not touch the rejected transport).
func (s *Server) ServeConn(c protocol.Conn) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrServerClosed
	}
	if s.active {
		s.mu.Unlock()
		return ErrSessionBusy
	}
	s.active = true
	s.mu.Unlock()
	defer s.release()

	link := protocol.NewLink(c, s.cfg.Link)
	defer link.GracefulClose()

	sess := &Session{
		server: s,
		target: s.target,
		link:   link,
		log:    s.cfg.Logger,
	}
	sess.log.Printf("session: opened (strict-caps=%v idle=%s)", s.cfg.StrictCaps, s.cfg.IdleTimeout)

	if err := sess.negotiate(); err != nil {
		sess.log.Printf("session: rejected: %v", err)
		return err
	}
	return sess.loop()
}

// release detaches the session and guarantees the target is halted at a
// deterministic position after any disconnect/timeout.
func (s *Server) release() {
	// Best-effort stop: a running target is interrupted and left halted.
	if s.target.State() == target.StateRunning {
		_, _ = s.target.Interrupt()
	}
	s.mu.Lock()
	s.active = false
	s.mu.Unlock()
}

// negotiatedFeature names are the wire tokens used in qSupported.
const (
	capSWBreak    = "swbreak"
	capHWBreak    = "hwbreak"
	capMemMap     = "qXfer:memory-map"
	capRcmd       = "qRcmd"
	capPacketSize = "PacketSize"
	packetSize    = 1024
)

// serverFeatures is everything the server can offer, in wire order.
var serverFeatures = []string{
	capSWBreak + "+",
	capHWBreak + "+",
	capMemMap + "+",
	capRcmd + "+",
	fmt.Sprintf("%s=%x", capPacketSize, packetSize),
}

// negotiate performs the mandatory qSupported exchange.
func (sess *Session) negotiate() error {
	body, err := sess.recvPacket()
	if err != nil {
		return err
	}
	sess.log.Printf("frame <- %q", string(body))
	if !strings.HasPrefix(string(body), "qSupported") {
		_ = sess.sendError(ErrProtoFirstPacket, "first packet must be qSupported, got %q", body)
		return fmt.Errorf("%w: first packet %q", ErrCapabilityRejected, string(body))
	}
	caps, fatal := parseClientCaps(string(body))
	sess.caps = caps
	if fatal != "" {
		_ = sess.sendError(ErrProtoCaps, "%s", fatal)
		return fmt.Errorf("%w: %s", ErrCapabilityRejected, fatal)
	}
	// Required capability: hardware breakpoints are core to this server. In
	// strict mode a client that explicitly rejects them is refused; otherwise
	// the session degrades and software-breakpoint style use is unavailable.
	if sess.server.cfg.StrictCaps && explicitlyRejected(string(body), capHWBreak) {
		msg := "client rejected required capability " + capHWBreak
		_ = sess.sendError(ErrProtoCaps, "%s", msg)
		return fmt.Errorf("%w: %s", ErrCapabilityRejected, msg)
	}
	reply := "qSupported:" + strings.Join(serverFeatures, ";")
	_ = sess.sendRaw(reply)
	sess.log.Printf("caps: negotiated hwbreak=%v swbreak=%v maxPacket=%d (client=%d features)",
		caps.hwbreak, caps.swbreak, caps.maxPacketLen, caps.clientCount)
	return nil
}
