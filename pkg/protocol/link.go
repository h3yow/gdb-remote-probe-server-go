package protocol

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/clock"
)

// LinkOptions configures retransmission semantics.
type LinkOptions struct {
	// AckTimeout bounds waiting for '+' before a resend. 0 disables the timer
	// (a healthy connection then waits purely on the inbound ack; retry tests
	// set a timeout and drive a fake clock explicitly).
	AckTimeout time.Duration
	// MaxRetries bounds resends; total attempts are MaxRetries+1.
	MaxRetries int
	// Clock drives timeout timers. nil uses the wall clock.
	Clock clock.Clock
}

// DefaultLinkOptions are permissive settings for the demo.
func DefaultLinkOptions() LinkOptions {
	return LinkOptions{AckTimeout: 100 * time.Millisecond, MaxRetries: 3, Clock: clock.NewRealClock()}
}

type outbound struct {
	data    []byte
	written chan error // closed after the bytes reach the transport
}

// readEvent is one decoded result from the background reader.
type readEvent struct {
	frame     []byte
	hasFrame  bool // true for a decoded frame, including an empty ("$#00") body
	ctrl      byte // 0 or 0x03 (inbound '+/-' are routed, not queued)
	duplicate bool
}

// Link adds reliable frame exchange over a Conn. It runs two dedicated
// goroutines: a reader (decodes frames, pairs acks, requests acks) and a
// writer (serializes every outbound byte). This removes all read/write lock
// cycles, so both peers can acknowledge each other without deadlocking.
type Link struct {
	conn Conn
	opts LinkOptions

	outMu     sync.Mutex
	out       chan outbound
	outClosed bool

	readMu  sync.Mutex
	events  []readEvent
	notify  chan struct{}
	done    chan struct{} // closed once on shutdown
	readErr error
	closed  bool

	ackWaiterMu sync.Mutex
	ackWaiter   chan byte

	frames chan Frame // single long-lived stream of inbound frames/errors

	// dupMu guards pendingFrame: the last delivered frame still awaiting
	// consumption by Recv. A retransmitted identical frame is suppressed only
	// while pendingFrame is set; once Recv takes it, an identical new frame is
	// a genuinely new message and is delivered.
	dupMu        sync.Mutex
	pendingFrame string
	hasPending   bool

	closeOnce sync.Once
}

// NewLink wraps a transport and starts its reader and writer goroutines.
func NewLink(c Conn, opts LinkOptions) *Link {
	if opts.MaxRetries < 0 {
		opts.MaxRetries = 0
	}
	l := &Link{
		conn:   c,
		opts:   opts,
		out:    make(chan outbound, 1024),
		notify: make(chan struct{}),
		done:   make(chan struct{}),
		frames: make(chan Frame, 256),
	}
	go l.writeLoop()
	go l.readLoop()
	go l.framePump()
	return l
}

func (l *Link) clk() clock.Clock {
	if l.opts.Clock != nil {
		return l.opts.Clock
	}
	return clock.NewRealClock()
}

// write performs a serialized write through the writer goroutine.
func (l *Link) write(p []byte) error {
	l.outMu.Lock()
	closed := l.outClosed
	l.outMu.Unlock()
	if closed {
		return ErrClosed
	}
	ob := outbound{data: append([]byte(nil), p...), written: make(chan error, 1)}
	l.out <- ob
	return <-ob.written
}

// postControl queues a control byte ('+'/'-'). The outbound buffer is large
// and the writer drains it eagerly; acks are tiny, so this cannot fill in a
// correctly functioning connection.
func (l *Link) postControl(b byte) {
	ob := outbound{data: []byte{b}, written: make(chan error, 1)}
	l.outMu.Lock()
	closed := l.outClosed
	l.outMu.Unlock()
	if closed {
		return
	}
	l.out <- ob
}

func (l *Link) writeLoop() {
	for ob := range l.out {
		_, err := l.conn.Write(ob.data)
		ob.written <- err
	}
}

// readLoop drains the transport, decodes, routes '+/-' to the in-flight Send
// and enqueues frames/ctrl-c for Recv. It asks the writer to send acks, so it
// never blocks on the application and never holds a write lock.
func (l *Link) readLoop() {
	dec := NewDecoder()
	buf := make([]byte, 256)
	for {
		n, err := l.conn.Read(buf)
		if err != nil {
			l.fail(mapConnErr(err))
			return
		}
		res := dec.Push(buf[:n])
		var evs []readEvent
		for _, c := range res.Control {
			if c == EventAck || c == EventNack {
				l.routeAck(byte(c))
			} else {
				evs = append(evs, readEvent{ctrl: byte(c)})
			}
		}
		for range res.Errors {
			l.postControl(ByteNack)
		}
		for _, f := range res.Frames {
			l.postControl(ByteAck)
			if l.classifyFrame(f) {
				evs = append(evs, readEvent{duplicate: true})
			} else {
				evs = append(evs, readEvent{frame: f, hasFrame: true})
			}
		}
		if len(evs) > 0 {
			l.enqueue(evs)
		}
	}
}

// classifyFrame reports whether f is a retransmission to suppress. A frame is
// a duplicate only when it equals the previous frame that the application has
// not yet consumed; otherwise it is recorded as the new pending frame.
func (l *Link) classifyFrame(f []byte) bool {
	l.dupMu.Lock()
	defer l.dupMu.Unlock()
	s := string(f)
	if l.hasPending && s == l.pendingFrame {
		return true
	}
	l.pendingFrame = s
	l.hasPending = true
	return false
}

// consumePending clears the pending marker once a frame is handed to Recv.
func (l *Link) consumePending(body []byte) {
	l.dupMu.Lock()
	if l.hasPending && l.pendingFrame == string(body) {
		l.hasPending = false
		l.pendingFrame = ""
	}
	l.dupMu.Unlock()
}

func (l *Link) enqueue(evs []readEvent) {
	l.readMu.Lock()
	l.events = append(l.events, evs...)
	close(l.notify)
	l.notify = make(chan struct{})
	l.readMu.Unlock()
}

func (l *Link) fail(err error) {
	l.readMu.Lock()
	if !l.closed && l.readErr == nil {
		l.readErr = err
	}
	close(l.notify)
	l.notify = make(chan struct{})
	l.readMu.Unlock()
}

func (l *Link) routeAck(b byte) {
	l.ackWaiterMu.Lock()
	w := l.ackWaiter
	l.ackWaiterMu.Unlock()
	if w != nil {
		select {
		case w <- b:
		default:
		}
	}
}

// waitEvent blocks (loss-free via channel swap) until pred matches.
func (l *Link) waitEvent(pred func(readEvent) bool, timeout time.Duration) (readEvent, error) {
	for {
		var timerCh <-chan time.Time
		var timer clock.Timer
		if timeout > 0 {
			timer = l.clk().NewTimer(timeout)
			timerCh = timer.C()
		}
		l.readMu.Lock()
		// Already-queued events take priority over a terminal read error, so a
		// final frame that arrived in the same batch as an EOF/close is
		// delivered before Recv reports ErrClosed.
		for i := range l.events {
			if pred(l.events[i]) {
				ev := l.events[i]
				l.events = append(l.events[:i], l.events[i+1:]...)
				l.readMu.Unlock()
				if timer != nil {
					_ = timer.Stop()
				}
				return ev, nil
			}
		}
		if l.readErr != nil {
			l.readMu.Unlock()
			if timer != nil {
				_ = timer.Stop()
			}
			return readEvent{}, l.readErr
		}
		wake := l.notify
		l.readMu.Unlock()

		select {
		case <-wake:
		case <-timerCh:
			if timer != nil {
				_ = timer.Stop()
			}
			return readEvent{}, ErrTimeout
		case <-l.done:
			if timer != nil {
				_ = timer.Stop()
			}
			return readEvent{}, ErrClosed
		}
		if timer != nil {
			_ = timer.Stop()
		}
	}
}

// drainQueued forwards all currently queued frames/ctrl events once the
// connection has closed, preserving final in-flight data.
func (l *Link) drainQueued() {
	for {
		l.readMu.Lock()
		idx := -1
		var ev readEvent
		for i := range l.events {
			e := l.events[i]
			if e.hasFrame || e.duplicate || e.ctrl == ByteCtrlC {
				idx, ev = i, e
				break
			}
		}
		if idx >= 0 {
			l.events = append(l.events[:idx], l.events[idx+1:]...)
		}
		l.readMu.Unlock()
		if idx < 0 {
			return
		}
		if ev.ctrl == ByteCtrlC {
			l.deliver(Frame{Err: ErrInterrupted})
			continue
		}
		if ev.duplicate {
			continue
		}
		l.consumePending(ev.frame)
		l.deliver(Frame{Body: ev.frame})
	}
}

// framePump is the single forwarder from the decoded-event queue to Frames().
// It runs for the link's lifetime, so there is never more than one consumer
// draining waitEvent (per frame type) and no per-packet goroutines leak.
func (l *Link) framePump() {
	for {
		ev, err := l.waitEvent(func(e readEvent) bool {
			return e.hasFrame || e.duplicate || e.ctrl == ByteCtrlC
		}, 0)
		if err != nil {
			if errors.Is(err, ErrClosed) {
				// Drain any frames that were decoded just before the close so
				// the consumer observes the final data, not only the EOF.
				l.drainQueued()
				l.deliver(Frame{Err: ErrClosed})
				return
			}
			l.deliver(Frame{Err: mapConnErr(err)})
			continue
		}
		if ev.ctrl == ByteCtrlC {
			l.deliver(Frame{Err: ErrInterrupted})
			continue
		}
		if ev.duplicate {
			continue // suppressed retransmission
		}
		l.consumePending(ev.frame)
		l.deliver(Frame{Body: ev.frame})
	}
}

// deliver forwards one frame to the Frames stream. It selects on the shutdown
// signal so it can never send after Close or block a torn-down connection.
func (l *Link) deliver(f Frame) {
	select {
	case l.frames <- f:
	case <-l.done:
	}
}

// Frames is the long-lived inbound stream. Exactly one consumer should select
// on it together with Done (the session loop).
func (l *Link) Frames() <-chan Frame { return l.frames }

// Done is closed when the link shuts down; consumers select on it to unblock.
func (l *Link) Done() <-chan struct{} { return l.done }

// Send transmits one frame and pairs the inbound '+' with this transmission.
func (l *Link) Send(body []byte) error {
	frame := EncodeFrame(body)
	ackCh := make(chan byte, 1)
	var lastErr error
	for attempt := 0; attempt <= l.opts.MaxRetries; attempt++ {
		l.ackWaiterMu.Lock()
		l.ackWaiter = ackCh
		l.ackWaiterMu.Unlock()

		if err := l.write(frame); err != nil {
			l.clearAckWaiter(ackCh)
			return mapConnErr(err)
		}
		switch l.waitAck(ackCh) {
		case ByteAck:
			l.clearAckWaiter(ackCh)
			return nil
		case ByteNack:
			lastErr = ErrChecksum
		default:
			lastErr = ErrTimeout
		}
	}
	l.clearAckWaiter(ackCh)
	return fmt.Errorf("%w: no ack after %d attempts: %v (readErr=%v)",
		ErrTimeout, l.opts.MaxRetries+1, lastErr, l.snapshotReadErr())
}

func (l *Link) snapshotReadErr() error {
	l.readMu.Lock()
	defer l.readMu.Unlock()
	return l.readErr
}

func (l *Link) clearAckWaiter(ch chan byte) {
	l.ackWaiterMu.Lock()
	if l.ackWaiter == ch {
		l.ackWaiter = nil
	}
	l.ackWaiterMu.Unlock()
}

func (l *Link) waitAck(ch chan byte) byte {
	var timerCh <-chan time.Time
	var timer clock.Timer
	if l.opts.AckTimeout > 0 {
		timer = l.clk().NewTimer(l.opts.AckTimeout)
		defer timer.Stop()
		timerCh = timer.C()
	}
	for {
		select {
		case b := <-ch:
			return b
		case <-timerCh:
			return 0
		default:
		}
		l.readMu.Lock()
		err := l.readErr
		wake := l.notify
		l.readMu.Unlock()
		if err != nil {
			return 0
		}
		if timerCh == nil {
			select {
			case b := <-ch:
				return b
			case <-wake:
			case <-l.done:
				return 0
			}
		} else {
			select {
			case b := <-ch:
				return b
			case <-timerCh:
				return 0
			case <-wake:
			case <-l.done:
				return 0
			}
		}
	}
}

// Recv blocks until one new valid frame arrives.
func (l *Link) Recv() ([]byte, error) { return l.recv(0) }

// RecvTimeout behaves like Recv but returns ErrTimeout after d with no frame.
func (l *Link) RecvTimeout(d time.Duration) ([]byte, error) { return l.recv(d) }

func (l *Link) recv(d time.Duration) ([]byte, error) {
	if d <= 0 {
		f, ok := <-l.frames
		if !ok {
			return nil, ErrClosed
		}
		return f.Body, f.Err
	}
	t := l.clk().NewTimer(d)
	defer t.Stop()
	select {
	case f, ok := <-l.frames:
		if !ok {
			return nil, ErrClosed
		}
		return f.Body, f.Err
	case <-t.C():
		return nil, ErrTimeout
	}
}

// Frame is one delivered inbound item.
type Frame struct {
	Body []byte
	Err  error
}

// SendCtrl sends a raw control byte (typically 0x03), bypassing framing.
func (l *Link) SendCtrl(b byte) error {
	return mapConnErr(l.write([]byte{b}))
}

// GracefulClose closes after the reader has drained queued frames.
func (l *Link) GracefulClose() error { return l.Close() }

// Close stops the goroutines and closes the transport. After Close the Frames
// channel is closed so any blocked consumer is released.
func (l *Link) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.readMu.Lock()
		l.closed = true
		l.readMu.Unlock()
		err := l.conn.Close()
		l.fail(ErrClosed)
		l.outMu.Lock()
		if !l.outClosed {
			l.outClosed = true
			close(l.out)
		}
		l.outMu.Unlock()
		_ = err
	})
	return nil
}

func mapConnErr(err error) error {
	if err == nil {
		return nil
	}
	if err == io.EOF {
		return ErrClosed
	}
	return err
}
