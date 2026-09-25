// Package protocol implements the GDB Remote Serial Protocol (RSP)
// framing layer and packet command set used by the probe server.
package protocol

import "time"

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

type realClock struct{}

// RealClock uses the host wall clock.
func RealClock() Clock { return realClock{} }

func (realClock) Now() time.Time                         { return time.Time{} }
func (realClock) NewTimer(d time.Duration) Timer         { return nil }

// FakeClock returns a clock whose timers only fire when Advance is
// called. Timers created with d<=0 fire immediately on the next goroutine
// schedule point.
type FakeClock interface {
	Clock
	Advance(d time.Duration)
}

// NewFakeClock constructs a controllable fake clock.
func NewFakeClock() FakeClock { return nil }
