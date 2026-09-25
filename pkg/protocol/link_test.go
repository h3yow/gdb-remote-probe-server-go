package protocol

import (
	"errors"
	"testing"
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/clock"
)

func fakeOpts(fc *clock.FakeClock) LinkOptions {
	return LinkOptions{AckTimeout: 10 * time.Millisecond, MaxRetries: 3, Clock: fc}
}

func testLinks(t *testing.T, a, b LinkOptions) (*Link, *Link) {
	t.Helper()
	ca, cb := NewPipe()
	return NewLink(ca, a), NewLink(cb, b)
}

// pumpTime drives fake time by jumping to the next pending timer deadline.
// Because time never advances past an uncreated or future timer, a sender
// cannot spuriously exhaust its retries before the peer gets scheduled.
func pumpTime(fc *clock.FakeClock, done <-chan struct{}) {
	for fc.AdvanceToNext(done) {
	}
}

func TestLinkRoundTrip(t *testing.T) {
	fc := clock.NewFakeClock(time.Unix(0, 0))
	a, b := testLinks(t, fakeOpts(fc), fakeOpts(fc))
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	done := make(chan error, 1)
	go func() { done <- a.Send([]byte("qSupported")) }()

	body, err := b.Recv()
	if err != nil || string(body) != "qSupported" {
		t.Fatalf("recv: %q %v", body, err)
	}
	if err := <-done; err != nil {
		t.Fatalf("send ack: %v", err)
	}
}

func TestLinkNackRetransmit(t *testing.T) {
	fc := clock.NewFakeClock(time.Unix(0, 0))
	ca, cb := NewPipe()
	ca.SetImpair(Impair{CorruptFirstFrames: 1})
	a := NewLink(ca, fakeOpts(fc))
	b := NewLink(cb, fakeOpts(fc))
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	sent := make(chan error, 1)
	go func() { sent <- a.Send([]byte("g")) }()

	body, err := b.Recv()
	if err != nil || string(body) != "g" {
		t.Fatalf("recv after nack: %q %v", body, err)
	}
	if err := <-sent; err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestLinkDroppedFrameTimeoutRetry(t *testing.T) {
	// First frame is dropped. The sender times out (real clock) and retransmits
	// the identical frame, which is then delivered and acknowledged.
	ca, cb := NewPipe()
	ca.SetImpair(Impair{DropFirstFrames: 1})
	opts := LinkOptions{AckTimeout: 20 * time.Millisecond, MaxRetries: 5}
	a := NewLink(ca, opts)
	b := NewLink(cb, opts)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	sent := make(chan error, 1)
	go func() { sent <- a.Send([]byte("m1000,4")) }()

	body, err := b.Recv()
	if err != nil || string(body) != "m1000,4" {
		t.Fatalf("retry delivery: %q %v", body, err)
	}
	if err := <-sent; err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestLinkDuplicateSuppressed(t *testing.T) {
	fc := clock.NewFakeClock(time.Unix(0, 0))
	ca, cb := NewPipe()
	ca.SetImpair(Impair{DuplicateFirstFrames: 1})
	a := NewLink(ca, fakeOpts(fc))
	b := NewLink(cb, fakeOpts(fc))
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	got := make(chan string, 1)
	go func() {
		body, _ := b.Recv()
		got <- string(body)
	}()
	if err := a.Send([]byte("z0,1000")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if body := <-got; body != "z0,1000" {
		t.Fatalf("delivered body: %q", body)
	}

	go func() {
		body, _ := b.Recv()
		got <- string(body)
	}()
	if err := a.Send([]byte("g")); err != nil {
		t.Fatalf("send2: %v", err)
	}
	if body := <-got; body != "g" {
		t.Fatalf("second delivery: %q", body)
	}
}

func TestLinkHalfPackets(t *testing.T) {
	fc := clock.NewFakeClock(time.Unix(0, 0))
	ca, cb := NewPipe()
	ca.SetImpair(Impair{FragmentSize: 3})
	a := NewLink(ca, fakeOpts(fc))
	b := NewLink(cb, fakeOpts(fc))
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	done := make(chan error, 1)
	go func() { done <- a.Send([]byte("m2000,10")) }()
	body, err := b.Recv()
	if err != nil || string(body) != "m2000,10" {
		t.Fatalf("half-packet recv: %q %v", body, err)
	}
	if err := <-done; err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestLinkCtrlC(t *testing.T) {
	fc := clock.NewFakeClock(time.Unix(0, 0))
	a, b := testLinks(t, fakeOpts(fc), fakeOpts(fc))
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	got := make(chan error, 1)
	go func() { _, err := b.Recv(); got <- err }()
	if err := a.SendCtrl(ByteCtrlC); err != nil {
		t.Fatal(err)
	}
	if err := <-got; !errors.Is(err, ErrInterrupted) {
		t.Fatalf("want ErrInterrupted, got %v", err)
	}
}

func TestLinkCloseUnblocks(t *testing.T) {
	fc := clock.NewFakeClock(time.Unix(0, 0))
	a, b := testLinks(t, fakeOpts(fc), fakeOpts(fc))
	got := make(chan error, 1)
	go func() { _, err := b.Recv(); got <- err }()
	_ = a.Close()
	if err := <-got; !errors.Is(err, ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
	_ = b.Close()
}

func TestLinkAckNeverComes(t *testing.T) {
	fc := clock.NewFakeClock(time.Unix(0, 0))
	ca, cb := NewPipe()
	ca.SetImpair(Impair{Stall: true}) // frames never reach b; no acks
	a := NewLink(ca, LinkOptions{AckTimeout: time.Millisecond, MaxRetries: 1, Clock: fc})
	b := NewLink(cb, fakeOpts(fc))
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	errCh := make(chan error, 1)
	go func() { errCh <- a.Send([]byte("g")) }()
	pumpDone := make(chan struct{})
	go pumpTime(fc, pumpDone)
	err := <-errCh
	close(pumpDone)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
}

func TestLinkLateAckTolerated(t *testing.T) {
	fc := clock.NewFakeClock(time.Unix(0, 0))
	ca, cb := NewPipe()
	a := NewLink(ca, fakeOpts(fc))
	b := NewLink(cb, fakeOpts(fc))
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	// First: a normal exchange to establish lastFrame on both sides.
	done := make(chan error, 1)
	go func() { done <- a.Send([]byte("g")) }()
	if _, err := b.Recv(); err != nil {
		t.Fatal(err)
	}
	<-done

	// Simulate a late/duplicate '+' arriving before the next send: it simply
	// sits in a's event queue and is consumed by the next Send, no desync.
	go func() {
		// b's reader acks on its own receives; inject an explicit '+' toward a.
		_ = b.SendCtrl(ByteAck)
	}()
	done2 := make(chan error, 1)
	go func() { done2 <- a.Send([]byte("m0,4")) }()
	body, err := b.Recv()
	if err != nil || string(body) != "m0,4" {
		t.Fatalf("late-ack exchange: %q %v", body, err)
	}
	if err := <-done2; err != nil {
		t.Fatalf("send after late ack: %v", err)
	}
}
