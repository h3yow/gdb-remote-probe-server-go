// Package protocol implements the GDB Remote Serial Protocol (RSP)
// framing layer and packet command set used by the probe server.
package protocol

import (
	"sync"
	"time"
)

// Clock abstracts time so that retransmission and deadline behaviour is
// deterministic in tests without fixed-duration sleeps.
type Clock interface {
	Now() time.Time
	NewTimer(d time.Duration) Timer
}

// Timer is a cancellable timer, analogous to time.Timer.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(d time.Duration) bool
}

// FakeClock is a Clock whose timers only fire through Advance, letting
// tests drive retransmission deterministically.
type FakeClock interface {
	Clock
	Advance(d time.Duration)
}

type realClock struct{}

// RealClock uses the host wall clock.
func RealClock() Clock { return realClock{} }

func (realClock) Now() time.Time { return time.Now() }

func (realClock) NewTimer(d time.Duration) Timer {
	return &realTimer{t: time.NewTimer(d)}
}

type realTimer struct {
	t *time.Timer
}

func (r *realTimer) C() <-chan time.Time { return r.t.C }
func (r *realTimer) Stop() bool          { return r.t.Stop() }
func (r *realTimer) Reset(d time.Duration) bool {
	return r.t.Reset(d)
}

// fakeClock implements Clock for deterministic tests. Timers never fire
// on their own; a test calls Advance to expire due timers. Timers created
// with a non-positive duration expire immediately on creation.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
	nextID uint64
}

type fakeTimer struct {
	clock *fakeClock
	id    uint64
	ch    chan time.Time

	mu      sync.Mutex
	fired   bool
	stopped bool
	when    time.Time
}

// NewFakeClock starts at a fixed epoch.
func NewFakeClock() FakeClock {
	return &fakeClock{now: time.Unix(1_700_000_000, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	c.nextID++
	t := &fakeTimer{
		clock: c,
		id:    c.nextID,
		ch:    make(chan time.Time, 1),
		when:  c.now.Add(d),
	}
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	if d <= 0 {
		t.fire(c.now)
	}
	return t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	due := make([]*fakeTimer, 0)
	kept := c.timers[:0]
	for _, t := range c.timers {
		t.mu.Lock()
		if !t.stopped && !t.fired && !t.when.After(now) {
			due = append(due, t)
		} else if !t.stopped {
			kept = append(kept, t)
		}
		t.mu.Unlock()
	}
	c.timers = kept
	c.mu.Unlock()
	for _, t := range due {
		t.fire(now)
	}
}

func (t *fakeTimer) fire(at time.Time) {
	t.mu.Lock()
	if t.fired || t.stopped {
		t.mu.Unlock()
		return
	}
	t.fired = true
	t.mu.Unlock()
	select {
	case t.ch <- at:
	default:
	}
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	wasActive := !t.fired && !t.stopped
	t.stopped = true
	return wasActive
}

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.mu.Lock()
	wasActive := !t.fired && !t.stopped
	t.fired = false
	t.stopped = false
	t.when = t.clock.Now().Add(d)
	// drain any buffered value
	select {
	case <-t.ch:
	default:
	}
	t.mu.Unlock()
	t.clock.register(t)
	if d <= 0 {
		t.fire(t.clock.Now())
	}
	return wasActive
}

func (c *fakeClock) register(t *fakeTimer) {
	c.mu.Lock()
	c.timers = append(c.timers, t)
	c.mu.Unlock()
}
