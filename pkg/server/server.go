// Package server wires transport, framing, command dispatch and session
// management into a runnable probe server.
package server

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/protocol"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/session"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

// Config configures a Server.
type Config struct {
	ImagePath  string
	TargetName string
	Listen     string
	IdleTimeout time.Duration
	Clock      protocol.Clock
	Log        protocol.Logger
}

// Server is the local probe server. It serves one target with an
// at-most-one-active-session policy.
type Server struct {
	cfg  Config
	mgr  *session.Manager
	ln   net.Listener
}

// New constructs a server and loads the configured image.
func New(cfg Config) (*Server, error) { return nil, nil }

// Listen starts accepting connections.
func (s *Server) Listen(ctx context.Context) error { return nil }

// Addr returns the bound listen address.
func (s *Server) Addr() net.Addr { return nil }

// Close stops the listener and releases all sessions.
func (s *Server) Close() error { return nil }

// handleConn runs the protocol loop for one connection. Exposed for tests
// with in-memory transports.
func (s *Server) handleConn(ctx context.Context, conn io.ReadWriter) {}

// ServeSession runs one session loop over an arbitrary transport and
// returns when the connection ends, the session detaches, or ctx is
// cancelled. Deterministic: no fixed-duration sleeps are required for
// state convergence.
func (s *Server) ServeSession(ctx context.Context, sess *session.Session, fr *protocol.Framer) error {
	return nil
}

// LoadedImage exposes the loaded image (test helper).
func (s *Server) LoadedImage() *target.Image { return nil }
