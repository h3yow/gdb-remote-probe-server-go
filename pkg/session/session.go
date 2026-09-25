// Package session owns target lifecycle and the at-most-one-active-session
// invariant for a debug target.
package session

import (
	"context"
	"sync"
	"sync/atomic"

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

func (s Status) String() string {
	switch s {
	case StatusActive:
		return "active"
	case StatusDetached:
		return "detached"
	case StatusKilled:
		return "killed"
	default:
		return "idle"
	}
}

// Manager owns targets and sessions keyed by image name. At most one
// active session may exist per target; repeat loads of the same image
// return the same target so reconnects see an identical view.
type Manager struct {
	mu      sync.Mutex
	targets map[string]*managedTarget
}

type managedTarget struct {
	name  string
	image *target.Image

	target *target.Target

	// sessionMu serialises attach/detach/attach transitions.
	sessionMu sync.Mutex
	session   *Session
}

// NewManager creates an empty manager.
func NewManager() *Manager {
	return &Manager{targets: make(map[string]*managedTarget)}
}

// Load loads an image once. Loading the same name again returns the
// existing target without reloading (identical-view guarantee).
func (m *Manager) Load(name, path string) (*target.Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mt, ok := m.targets[name]; ok {
		return mt.target, nil
	}
	img, err := target.ReadImage(path)
	if err != nil {
		return nil, err
	}
	tg, err := target.NewTarget(img, target.DefaultOptions())
	if err != nil {
		return nil, err
	}
	mt := &managedTarget{name: name, image: img, target: tg}
	m.targets[name] = mt
	return tg, nil
}

// LoadImage registers an already-parsed image under name (test helper).
func (m *Manager) LoadImage(name string, img *target.Image) (*target.Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mt, ok := m.targets[name]; ok {
		return mt.target, nil
	}
	tg, err := target.NewTarget(img, target.DefaultOptions())
	if err != nil {
		return nil, err
	}
	mt := &managedTarget{name: name, image: img, target: tg}
	m.targets[name] = mt
	return tg, nil
}

// Target returns a previously loaded target.
func (m *Manager) Target(name string) *target.Target {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mt, ok := m.targets[name]; ok {
		return mt.target
	}
	return nil
}

var sessionID uint64

// Attach attempts to open a session on the named target. A second
// concurrent or conflicting attach fails with CodeSessionBusy; existing
// state is never interleaved. The context only bounds waiting for manager
// bookkeeping; this implementation rejects immediately rather than queue.
func (m *Manager) Attach(ctx context.Context, name string) (*Session, error) {
	m.mu.Lock()
	mt, ok := m.targets[name]
	m.mu.Unlock()
	if !ok {
		return nil, &target.Error{Code: target.CodeSymbolNotFound, Op: "Attach",
			Detail: "target not loaded: " + name}
	}
	mt.sessionMu.Lock()
	defer mt.sessionMu.Unlock()
	if mt.session != nil {
		mt.session.mu.Lock()
		st := mt.session.status
		mt.session.mu.Unlock()
		if st == StatusActive {
			return nil, &target.Error{Code: target.CodeSessionBusy, Op: "Attach",
				Detail: "an active debug session already owns target " + name}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sess := &Session{
		id:     atomic.AddUint64(&sessionID, 1),
		status: StatusActive,
		mt:     mt,
	}
	mt.session = sess
	return sess, nil
}

// Active reports whether a session is currently active for name.
func (m *Manager) Active(name string) bool {
	m.mu.Lock()
	mt, ok := m.targets[name]
	m.mu.Unlock()
	if !ok {
		return false
	}
	mt.sessionMu.Lock()
	defer mt.sessionMu.Unlock()
	return mt.session != nil && mt.session.Status() == StatusActive
}

// Close releases all targets. Active sessions are detached first.
func (m *Manager) Close() error {
	m.mu.Lock()
	mts := make([]*managedTarget, 0, len(m.targets))
	for _, mt := range m.targets {
		mts = append(mts, mt)
	}
	m.mu.Unlock()
	for _, mt := range mts {
		mt.sessionMu.Lock()
		if mt.session != nil && mt.session.Status() == StatusActive {
			_ = mt.session.detachLocked()
		}
		mt.sessionMu.Unlock()
	}
	m.mu.Lock()
	m.targets = make(map[string]*managedTarget)
	m.mu.Unlock()
	return nil
}

// Session is one debug connection bound to one target.
type Session struct {
	mu     sync.Mutex
	status Status
	id     uint64
	mt     *managedTarget
}

// ID returns the unique session identifier.
func (s *Session) ID() uint64 { return s.id }

// Target returns the bound target.
func (s *Session) Target() *target.Target { return s.mt.target }

// Status returns the lifecycle status.
func (s *Session) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// Detach ends the session deterministically, leaving the target stopped
// in its current state and immediately reusable. Idempotent.
func (s *Session) Detach() error {
	s.mt.sessionMu.Lock()
	defer s.mt.sessionMu.Unlock()
	return s.detachLocked()
}

func (s *Session) detachLocked() error {
	s.mu.Lock()
	if s.status != StatusActive {
		s.mu.Unlock()
		return nil // idempotent
	}
	s.status = StatusDetached
	tg := s.mt.target
	s.mu.Unlock()
	// Converge the target to a stopped terminal state.
	if tg.IsRunning() {
		_ = tg.Interrupt()
	}
	s.mt.session = nil
	return nil
}

// Kill ends the session and resets the target to its image entry.
// Idempotent.
func (s *Session) Kill() error {
	s.mt.sessionMu.Lock()
	defer s.mt.sessionMu.Unlock()
	s.mu.Lock()
	if s.status != StatusActive {
		s.mu.Unlock()
		return nil
	}
	s.status = StatusKilled
	tg := s.mt.target
	s.mu.Unlock()
	if tg.IsRunning() {
		_ = tg.Interrupt()
	}
	if err := tg.Reset(); err != nil {
		return err
	}
	s.mt.session = nil
	return nil
}
