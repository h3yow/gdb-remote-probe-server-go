// Package server wires transport, framing, command dispatch and session
// management into a runnable probe server.
package server

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/protocol"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/session"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

// Config configures a Server.
type Config struct {
	ImagePath   string
	TargetName  string
	Listen      string
	IdleTimeout time.Duration
	Clock       protocol.Clock
	Log         protocol.Logger
}

// Server is the local probe server. It serves one target with an
// at-most-one-active-session policy.
type Server struct {
	cfg Config
	mgr *session.Manager
	ln  net.Listener

	mu     sync.Mutex
	closed bool
}

type stdLogger struct{ l *log.Logger }

func (s stdLogger) Printf(format string, args ...interface{}) {
	s.l.Printf(format, args...)
}

// New constructs a server and loads the configured image.
func New(cfg Config) (*Server, error) {
	if cfg.TargetName == "" {
		cfg.TargetName = "target0"
	}
	if cfg.Clock == nil {
		cfg.Clock = protocol.RealClock()
	}
	if cfg.Log == nil {
		cfg.Log = stdLogger{l: log.New(os.Stderr, "probe: ", log.LstdFlags|log.Lmicroseconds)}
	}
	mgr := session.NewManager()
	if _, err := mgr.Load(cfg.TargetName, cfg.ImagePath); err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, mgr: mgr}, nil
}

// Listen starts accepting connections and blocks until ctx is cancelled.
func (s *Server) Listen(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	s.ln = ln
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn)
	}
}

// Addr returns the bound listen address.
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Close stops the listener and releases all sessions.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if s.ln != nil {
		_ = s.ln.Close()
	}
	return s.mgr.Close()
}

// LoadedImage exposes the loaded image (test helper).
func (s *Server) LoadedImage() *target.Image {
	tg := s.mgr.Target(s.cfg.TargetName)
	if tg == nil {
		return nil
	}
	return tg.Image()
}

// Manager exposes the session manager (test helper).
func (s *Server) Manager() *session.Manager { return s.mgr }

func (s *Server) handleConn(ctx context.Context, conn io.ReadWriter) {
	if c, ok := conn.(net.Conn); ok {
		defer c.Close()
	}
	sess, err := s.mgr.Attach(ctx, s.cfg.TargetName)
	if err != nil {
		s.cfg.Log.Printf("session rejected: %v", err)
		busy := []byte("E" + hex2(target.CodeSessionBusy))
		_, _ = conn.Write(protocol.EncodePacket(busy))
		if c, ok := conn.(io.Closer); ok {
			_ = c.Close()
		}
		return
	}
	fr := protocol.NewFramer(conn, protocol.DefaultFramerConfig())
	defer fr.Close()
	_ = s.serveSession(ctx, sess, fr)
}

// ServeSession runs the protocol loop over an arbitrary framed transport.
// 'c' resumes the target; while it runs only a raw 0x03 interrupt is
// accepted and every other packet is rejected with CodeTargetRunning, so
// requests never interleave.
func (s *Server) ServeSession(ctx context.Context, sess *session.Session, fr *protocol.Framer) error {
	return s.serveSession(ctx, sess, fr)
}

func (s *Server) serveSession(ctx context.Context, sess *session.Session, fr *protocol.Framer) error {
	d := protocol.NewDispatcher(sess.Target(), s.cfg.Log)
	var lastPacket string
	var lastReply []byte

	// Idle timeout is applied per receive call; no long-lived timer state
	// is needed, so a silent session converges deterministically.
	idle := s.cfg.IdleTimeout
	_ = time.Second
	resetIdle := func() {}

	for {
		frame, err := recvWithIdle(ctx, fr, idle)
		if err != nil {
			s.cfg.Log.Printf("connection ended: %v session=%d state=%s",
				err, sess.ID(), sess.Status())
			return s.cleanup(sess)
		}
		resetIdle()

		if frame.Kind == protocol.FrameInterrupt {
			s.cfg.Log.Printf("interrupt received session=%d running=%v",
				sess.ID(), sess.Target().IsRunning())
			if sess.Target().IsRunning() {
				_ = sess.Target().Interrupt()
				reason := sess.Target().WaitStopped()
				s.cfg.Log.Printf("stopped via interrupt reason=%s pc=%#x session=%d state=stopped",
					reason.Kind, reason.PC, sess.ID())
				if err := fr.SendPacket(ctx, protocol.ReplyForStop(reason)); err != nil {
					return s.cleanup(sess)
				}
			} else {
				// An interrupt while stopped carries no reply in strict
				// RSP; ack the next packet normally, do nothing.
			}
			continue
		}

		body := frame.Data
		s.cfg.Log.Printf("dispatch %q session=%d state=%s",
			string(body), sess.ID(), sess.Status())

		// Idempotent replay: an immediately retransmitted synchronous
		// packet (same as the last fully-answered command) gets the cached
		// reply instead of executing twice. Target mutations are absolute
		// and therefore safe to replay. The asynchronous resume ('c') is
		// never replayed because its reply is a state transition that must
		// occur afresh; the target handles breakpoint hits idempotently.
		if string(body) == lastPacket && string(body) != "c" {
			s.cfg.Log.Printf("replay cached reply %q for duplicate %q session=%d",
				lastReply, string(body), sess.ID())
			if err := fr.SendPacket(ctx, lastReply); err != nil {
				return s.cleanup(sess)
			}
			continue
		}

		reply := d.Dispatch(body)
		if string(body) == "QStartNoAckMode" && string(reply) == "OK" {
			fr.SetNoAckMode()
		}

		if d.ResumePending() {
			d.ClearResumePending()
			if err := sess.Target().Resume(); err != nil {
				s.cfg.Log.Printf("resume rejected: %v session=%d", err, sess.ID())
				errb := []byte("E" + hex2(target.CodeOf(err)))
				_ = fr.SendPacket(ctx, errb)
				lastPacket = string(body)
				lastReply = append([]byte(nil), errb...)
				continue
			}
			s.cfg.Log.Printf("target resumed session=%d state=running", sess.ID())
			stopReply, err := s.runUntilStop(ctx, sess, fr, idle)
			if err != nil {
				return err
			}
			if err := fr.SendPacket(ctx, stopReply); err != nil {
				return s.cleanup(sess)
			}
			lastPacket = string(body)
			lastReply = append([]byte(nil), stopReply...)
			continue
		}

		switch string(body) {
		case "D":
			s.cfg.Log.Printf("detach session=%d state=active -> detached", sess.ID())
			_ = fr.SendPacket(ctx, reply)
			return sess.Detach()
		case "k":
			s.cfg.Log.Printf("kill session=%d state=active -> killed", sess.ID())
			_ = fr.SendPacket(ctx, reply)
			return sess.Kill()
		}
		if reply == nil {
			reply = []byte("")
		}
		lastPacket = string(body)
		lastReply = append([]byte(nil), reply...)
		if err := fr.SendPacket(ctx, reply); err != nil {
			return s.cleanup(sess)
		}
	}
}

// runUntilStop waits for the target to stop. The only accepted inbound
// element is a raw 0x03 interrupt; packets are refused. Disconnects
// deterministically detach the session and converge the target to stopped.
func (s *Server) runUntilStop(ctx context.Context, sess *session.Session, fr *protocol.Framer, idle time.Duration) ([]byte, error) {
	for sess.Target().IsRunning() {
		frame, err := recvWithIdle(ctx, fr, idle)
		if err != nil {
			s.cfg.Log.Printf("disconnect while running: %v session=%d -> converge detach",
				err, sess.ID())
			if derr := sess.Detach(); derr != nil {
				return nil, derr
			}
			return nil, err
		}
		if frame.Kind == protocol.FrameInterrupt {
			s.cfg.Log.Printf("interrupt during resume session=%d", sess.ID())
			_ = sess.Target().Interrupt()
			continue
		}
		// Conflicting command while the target is running: it is rejected
		// rather than executed. No reply is emitted because the in-flight
		// 'c' owns the single reply channel; answering here would interleave
		// two responses on one command slot. The rejection reason is logged.
		s.cfg.Log.Printf("reject running packet %q session=%d reason=target-running",
			string(frame.Data), sess.ID())
	}
	reason := sess.Target().WaitStopped()
	s.cfg.Log.Printf("stopped reason=%s pc=%#x hits=%d session=%d state=stopped",
		reason.Kind, reason.PC, reason.Hits, sess.ID())
	return protocol.ReplyForStop(reason), nil
}

func (s *Server) cleanup(sess *session.Session) error {
	if sess.Status() == session.StatusActive {
		return sess.Detach()
	}
	return nil
}

// recvWithIdle returns the next frame or an idle-timeout error. The wait
// happens in a single select inside the framer, so no goroutine is
// spawned and cancellation cannot race frame delivery.
func recvWithIdle(ctx context.Context, fr *protocol.Framer, idle time.Duration) (protocol.Frame, error) {
	frame, err := fr.RecvPacketIdle(ctx, idle)
	if errors.Is(err, protocol.ErrIdleTimeout) {
		return protocol.Frame{}, &target.Error{Code: target.CodeTimeout, Op: "idle",
			Detail: "idle session timeout"}
	}
	return frame, err
}

func hex2(c target.Code) string {
	v := byte(c)
	const digits = "0123456789abcdef"
	return string([]byte{digits[v>>4], digits[v&0x0F]})
}
