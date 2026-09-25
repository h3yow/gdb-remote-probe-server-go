// Package clock abstracts time so that timeout and retransmission behavior is
// fully deterministic in tests. Tests advance a FakeClock explicitly instead
// of sleeping; production code uses the wall clock.
package clock

import (
	"sort"
	"sync"
	"time"
)

// Clock abstracts time.
type Clock interface {
	Now() time.Time
	NewTimer(d time.Duration) Timer
}

// Timer is a minimal timer handle modeled on time.Timer.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(d time.Duration)
}

// ---------------------------------------------------------------------------
// Wall clock
// ---------------------------------------------------------------------------

type realClock struct{}

// NewRealClock returns a clock backed by the wall clock.
func NewRealClock() Clock { return realClock{} }

func (realClock) Now() time.Time                 { return time.Now() }
func (realClock) NewTimer(d time.Duration) Timer { return &realTimer{t: time.NewTimer(d)} }

type realTimer struct{ t *time.Timer }

func (r *realTimer) C() <-chan time.Time { return r.t.C }
func (r *realTimer) Stop() bool          { return r.t.Stop() }
func (r *realTimer) Reset(d time.Duration) {
	if !r.t.Stop() {
		select {
		case <-r.t.C:
		default:
		}
	}
	r.t.Reset(d)
}

// ---------------------------------------------------------------------------
// Fake clock
// ---------------------------------------------------------------------------

type fakeTimer struct {
	id       uint64
	deadline time.Time
	ch       chan time.Time
}

type timerHandle struct {
	c *FakeClock
	t *fakeTimer
}

func (h *timerHandle) C() <-chan time.Time   { return h.t.ch }
func (h *timerHandle) Stop() bool            { return h.c.remove(h.t.id) }
func (h *timerHandle) Reset(d time.Duration) { h.c.reset(h.t, d) }

// FakeClock is a manually driven clock. Timers fire only inside Advance, so
// tests never sleep and ordering is deterministic.
type FakeClock struct {
	mu     sync.Mutex
	now    time.Time
	nextID uint64
	timers map[uint64]*fakeTimer
	// change is closed and replaced whenever the timer set changes or time
	// advances; waiters subscribe to it under mu, so no event is lost.
	change chan struct{}
}

// NewFakeClock returns a fake clock starting at t0.
func NewFakeClock(t0 time.Time) *FakeClock {
	return &FakeClock{
		now:    t0,
		timers: make(map[uint64]*fakeTimer),
		change: make(chan struct{}),
	}
}

// Changed subscribes to a change channel while f runs under the clock lock.
// The returned channel is closed on the next timer add/remove/fire or time
// advance. Subscribing under the lock makes wake-up loss impossible.
func (c *FakeClock) Changed() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.change
}

func (c *FakeClock) signalLocked() {
	close(c.change)
	c.change = make(chan struct{})
}

// Now returns the fake current time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// NewTimer creates a timer expiring d fake-time after Now().
func (c *FakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	c.nextID++
	t := &fakeTimer{
		id:       c.nextID,
		deadline: c.now.Add(d),
		ch:       make(chan time.Time, 1),
	}
	c.timers[t.id] = t
	c.signalLocked()
	c.mu.Unlock()
	return &timerHandle{c: c, t: t}
}

func (c *FakeClock) remove(id uint64) bool {
	c.mu.Lock()
	_, ok := c.timers[id]
	delete(c.timers, id)
	if ok {
		c.signalLocked()
	}
	c.mu.Unlock()
	return ok
}

func (c *FakeClock) reset(t *fakeTimer, d time.Duration) {
	c.mu.Lock()
	t.deadline = c.now.Add(d)
	c.timers[t.id] = t
	select {
	case <-t.ch:
	default:
	}
	c.signalLocked()
	c.mu.Unlock()
}

// Advance moves fake time forward by d and fires every timer whose deadline is
// reached, in deadline order. Fired timers are detached from the clock.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	due := make([]*fakeTimer, 0, len(c.timers))
	for id, t := range c.timers {
		if !t.deadline.After(c.now) {
			due = append(due, t)
			delete(c.timers, id)
		}
	}
	c.signalLocked()
	c.mu.Unlock()

	sort.Slice(due, func(i, j int) bool { return due[i].deadline.Before(due[j].deadline) })
	for _, t := range due {
		select {
		case t.ch <- t.deadline:
		default:
		}
	}
}

// AdvanceToNext moves fake time directly to the earliest pending timer
// deadline and fires due timers. It returns false when no timer is armed (or
// stop closes), letting a test driver block until one appears first. This is
// the deterministic driver primitive: time never advances past an uncreated
// timer, so in-flight operations cannot spuriously time out.
func (c *FakeClock) AdvanceToNext(stop <-chan struct{}) bool {
	if !c.WaitForTimers(stop) {
		return false
	}
	c.mu.Lock()
	var next time.Time
	for _, t := range c.timers {
		if next.IsZero() || t.deadline.Before(next) {
			next = t.deadline
		}
	}
	if d := next.Sub(c.now); d > 0 {
		c.now = next
	}
	due := make([]*fakeTimer, 0, len(c.timers))
	for id, t := range c.timers {
		if !t.deadline.After(c.now) {
			due = append(due, t)
			delete(c.timers, id)
		}
	}
	c.signalLocked()
	c.mu.Unlock()

	sort.Slice(due, func(i, j int) bool { return due[i].deadline.Before(due[j].deadline) })
	for _, t := range due {
		select {
		case t.ch <- t.deadline:
		default:
		}
	}
	return true
}

// WaitForTimers blocks until at least one armed timer exists or stop closes.
// It subscribes to changes under the lock, so a timer added concurrently can
// never be missed. No goroutine is created.
func (c *FakeClock) WaitForTimers(stop <-chan struct{}) bool {
	for {
		c.mu.Lock()
		if len(c.timers) > 0 {
			c.mu.Unlock()
			return true
		}
		ch := c.change
		c.mu.Unlock()

		select {
		case <-ch:
		case <-stop:
			return false
		}
	}
}

// PendingTimers reports how many armed timers currently exist.
func (c *FakeClock) PendingTimers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}
