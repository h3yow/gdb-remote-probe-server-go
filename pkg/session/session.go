// Package session owns target lifecycle and the at-most-one-active-session
// invariant for a debug target.
package session

import (
	"context"
	"io"
	"sync"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

// Status is the lifecycle state of a session.
type Status int

const (
	StatusIdle Status = iota
	StatusActive
	StatusDetached
	StatusKilled
)

func (s Status) String() string { return "" }

// Manager owns targets and sessions keyed by image name. At most one
// active session may exist per target; repeat loads of the same image
// return the same target so reconnects see an identical view.
type Manager struct {
	mu       sync.Mutex
	targets  map[string]*managedTarget
}

type managedTarget struct {
	name   string
	image  *target.Image
	target *target.Target

	sessionMu sync.Mutex
	session   *Session
}

// NewManager creates an empty manager.
func NewManager() *Manager { return nil }

// Load loads an image once. Loading the same name again returns the
// existing target without reloading (identical-view guarantee).
func (m *Manager) Load(name, path string) (*target.Target, error) { return nil, nil }

// Attach attempts to open a session on the named target. The second
// concurrent/conflicting attach fails with CodeSessionBusy.
func (m *Manager) Attach(ctx context.Context, name string, transport io.ReadWriter) (*Session, error) {
	return nil, nil
}

// Active reports whether a session is currently active.
func (m *Manager) Active(name string) bool { return false }

// Close releases all targets. Active sessions are detached first.
func (m *Manager) Close() error { return nil }

// Session is one debug connection bound to one target.
type Session struct {
	mu     sync.Mutex
	status Status
	id     uint64
	mt     *managedTarget
}

// Target returns the bound target.
func (s *Session) Target() *target.Target { return nil }

// Status returns the lifecycle status.
func (s *Session) Status() Status { return StatusIdle }

// Detach ends the session deterministically, leaving the target stopped
// in its current state and immediately reusable. Idempotent.
func (s *Session) Detach() error { return nil }

// Kill ends the session and resets the target to its image entry.
// Idempotent.
func (s *Session) Kill() error { return nil }
