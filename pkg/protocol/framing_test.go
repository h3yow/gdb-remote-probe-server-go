package protocol

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

// pipe is a scripted, deterministic in-memory transport.
type pipe struct {
	mu     sync.Mutex
	inbuf  bytes.Buffer // bytes for the framer to read
	outbuf bytes.Buffer // bytes the framer wrote
	cond   *sync.Cond
	closed bool
}

func newPipe() *pipe {
	p := &pipe{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *pipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	for p.inbuf.Len() == 0 && !p.closed {
		p.cond.Wait()
	}
	if p.inbuf.Len() == 0 {
		p.mu.Unlock()
		return 0, io.EOF
	}
	n, _ := p.inbuf.Read(b)
	p.mu.Unlock()
	return n, nil
}

func (p *pipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, io.ErrClosedPipe
	}
	return p.outbuf.Write(b)
}

func (p *pipe) feed(data []byte) {
	p.mu.Lock()
	p.inbuf.Write(data)
	p.cond.Broadcast()
	p.mu.Unlock()
}

func (p *pipe) output() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.outbuf.Bytes()...)
}

func testCfg(clock Clock) FramerConfig {
	return FramerConfig{
		AckTimeout:     time.Millisecond,
		MaxRetransmit:  2,
		MaxPacketBytes: 64,
		Clock:          clock,
	}
}

func TestValidPacketAndHalfPacket(t *testing.T) {
	p := newPipe()
	fc := NewFakeClock()
	f := NewFramer(p, testCfg(fc))
	defer f.Close()

	full := EncodePacket([]byte("g"))
	// deliver in two pieces (half packet)
	p.feed(full[:2])
	go func() {
		time.Sleep(time.Millisecond)
		p.feed(full[2:])
	}()
	fr, err := f.RecvPacket(context.Background())
	if err != nil {
		t.Fatalf("RecvPacket: %v", err)
	}
	if fr.Kind != FramePacket || string(fr.Data) != "g" {
		t.Fatalf("frame = %+v", fr)
	}
	out := p.output()
	if !bytes.Contains(out, []byte("+")) {
		t.Fatalf("server did not ack valid packet, out=%q", out)
	}
}

func TestBadChecksumNackAndResend(t *testing.T) {
	p := newPipe()
	fc := NewFakeClock()
	f := NewFramer(p, testCfg(fc))
	defer f.Close()

	bad := []byte("$g#ff") // wrong checksum (real is 67)
	p.feed(bad)
	// poll for the '-' nack deterministically (reader goroutine)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if bytes.Contains(p.output(), []byte("-")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no nack for corrupt packet, out=%q", p.output())
		}
		time.Sleep(time.Millisecond)
	}
	// corrupt packet must not be delivered
	select {
	case fr := <-f.frames:
		t.Fatalf("corrupt frame delivered: %+v", fr)
	default:
	}
	// then the client resends correctly
	p.feed(EncodePacket([]byte("g")))
	fr, err := f.RecvPacket(context.Background())
	if err != nil || string(fr.Data) != "g" {
		t.Fatalf("resent packet: %+v %v", fr, err)
	}
}

func TestDuplicatePacketDelivered(t *testing.T) {
	p := newPipe()
	f := NewFramer(p, DefaultFramerConfig())
	defer f.Close()

	pkt := EncodePacket([]byte("m0,4"))
	p.feed(pkt)
	fr, _ := f.RecvPacket(context.Background())
	if string(fr.Data) != "m0,4" {
		t.Fatalf("first delivery: %q", fr.Data)
	}
	// A retransmitted identical frame is delivered to the session layer,
	// which is responsible for idempotent reply replay (tested in
	// pkg/server). The framer still acks it.
	p.feed(pkt)
	fr2, err := f.RecvPacket(context.Background())
	if err != nil || string(fr2.Data) != "m0,4" {
		t.Fatalf("duplicate should be delivered for replay: %q %v", fr2.Data, err)
	}
}

func TestSendPacketAckRetransmitAndLateAck(t *testing.T) {
	p := newPipe()
	fc := NewFakeClock()
	f := NewFramer(p, testCfg(fc))
	defer f.Close()

	// First attempt: no ack, advance fake clock twice; ack finally
	// arrives before the third timeout.
	done := make(chan error, 1)
	go func() { done <- f.SendPacket(context.Background(), []byte("OK")) }()
	waitForWrites(t, p, 1) // attempt 1 on the wire
	fc.Advance(time.Millisecond)
	waitForWrites(t, p, 2) // retransmit attempt 2
	// late ack for attempt 1 satisfies attempt 2's wait
	p.feed([]byte("+"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendPacket: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendPacket never completed after ack")
	}
}

func TestSendPacketGivesUpAfterRetries(t *testing.T) {
	p := newPipe()
	fc := NewFakeClock()
	f := NewFramer(p, testCfg(fc))
	defer f.Close()

	done := make(chan error, 1)
	go func() { done <- f.SendPacket(context.Background(), []byte("OK")) }()
	for i := 0; i < 3; i++ {
		waitForWrites(t, p, i+1)
		fc.Advance(time.Millisecond)
	}
	err := <-done
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestInterruptFrame(t *testing.T) {
	p := newPipe()
	f := NewFramer(p, DefaultFramerConfig())
	defer f.Close()
	p.feed([]byte{0x03})
	fr, err := f.RecvPacket(context.Background())
	if err != nil || fr.Kind != FrameInterrupt {
		t.Fatalf("want interrupt frame, got %+v err=%v", fr, err)
	}
}

func TestNoAckModeSuppressesAcks(t *testing.T) {
	p := newPipe()
	f := NewFramer(p, DefaultFramerConfig())
	defer f.Close()
	f.SetNoAckMode()
	p.feed(EncodePacket([]byte("g")))
	if _, err := f.RecvPacket(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if bytes.Contains(p.output(), []byte("+")) {
		t.Fatalf("ack written in no-ack mode: %q", p.output())
	}
}

func waitForWrites(t *testing.T, p *pipe, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		count := bytes.Count(p.output(), []byte("$OK#"))
		if count >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d writes, want %d, out=%q", count, n, p.output())
		}
		time.Sleep(time.Millisecond)
	}
}
