package clock

import (
	"testing"
	"time"
)

func TestFakeTimerFiresOnAdvance(t *testing.T) {
	fc := NewFakeClock(time.Unix(0, 0))
	tm := fc.NewTimer(10 * time.Millisecond)
	fc.Advance(5 * time.Millisecond)
	select {
	case <-tm.C():
		t.Fatal("timer fired early")
	default:
	}
	fc.Advance(5 * time.Millisecond)
	select {
	case <-tm.C():
	default:
		t.Fatal("timer did not fire")
	}
	if fc.PendingTimers() != 0 {
		t.Fatalf("fired timer still pending: %d", fc.PendingTimers())
	}
}

func TestFakeTimerStopRemoves(t *testing.T) {
	fc := NewFakeClock(time.Unix(0, 0))
	tm := fc.NewTimer(10 * time.Millisecond)
	if !tm.Stop() {
		t.Fatal("Stop returned false for armed timer")
	}
	if fc.PendingTimers() != 0 {
		t.Fatal("stopped timer remains pending")
	}
	fc.Advance(20 * time.Millisecond)
	select {
	case <-tm.C():
		t.Fatal("stopped timer fired")
	default:
	}
}

func TestWaitForTimers(t *testing.T) {
	fc := NewFakeClock(time.Unix(0, 0))
	done := make(chan struct{})
	ready := make(chan bool, 1)
	go func() { ready <- fc.WaitForTimers(done) }()
	fc.NewTimer(time.Second)
	if !<-ready {
		t.Fatal("WaitForTimers did not observe timer")
	}
	close(done)
}
