package protocol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

// FrameKind identifies an inbound protocol element.
type FrameKind int

const (
	FramePacket    FrameKind = iota
	FrameInterrupt           // raw 0x03 byte
)

// Frame is one inbound protocol element.
type Frame struct {
	Kind FrameKind
	Data []byte // packet body without '$', '#', checksum for FramePacket
}

// FramerConfig tunes framing behaviour.
type FramerConfig struct {
	AckTimeout     time.Duration
	MaxRetransmit  int
	MaxPacketBytes int
	Clock          Clock
}

// DefaultFramerConfig returns production defaults.
func DefaultFramerConfig() FramerConfig {
	return FramerConfig{
		AckTimeout:    250 * time.Millisecond,
		MaxRetransmit: 3,
		// RSP has no length limit; bound it locally to keep corrupt input
		// from growing memory without bound.
		MaxPacketBytes: 4096,
		Clock:          RealClock(),
	}
}

// Framer implements RSP framing: '$' packet framing with two-digit hex
// checksum, '+'/'-' acknowledgements, retransmission, duplicate detection
// and raw 0x03 interrupt bytes. A reader goroutine demultiplexes the byte
// stream so acknowledgements interleaved with packets never corrupt state.
type Framer struct {
	cfg FramerConfig
	rw  io.ReadWriter

	frames  chan Frame
	readErr chan error
	ackSig  chan struct{} // buffered(1); posted for each received '+'

	closeOnce sync.Once
	closed    chan struct{}

	writeMu sync.Mutex
	ackMu   sync.Mutex
	ackMode bool
}

// NewFramer starts the reader loop for the given transport.
func NewFramer(rw io.ReadWriter, cfg FramerConfig) *Framer {
	if cfg.Clock == nil {
		cfg = DefaultFramerConfig()
	}
	if cfg.AckTimeout <= 0 {
		cfg.AckTimeout = DefaultFramerConfig().AckTimeout
	}
	if cfg.MaxRetransmit <= 0 {
		cfg.MaxRetransmit = DefaultFramerConfig().MaxRetransmit
	}
	if cfg.MaxPacketBytes <= 0 {
		cfg.MaxPacketBytes = DefaultFramerConfig().MaxPacketBytes
	}
	f := &Framer{
		cfg:     cfg,
		rw:      rw,
		frames:  make(chan Frame, 8),
		readErr: make(chan error, 1),
		ackSig:  make(chan struct{}, 1),
		closed:  make(chan struct{}),
		ackMode: true,
	}
	go f.readLoop()
	return f
}

// Close stops the reader goroutine and releases resources.
func (f *Framer) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

// SetNoAckMode disables outbound '+' acks and inbound ack waits after a
// successful QStartNoAckMode exchange.
func (f *Framer) SetNoAckMode() {
	f.ackMu.Lock()
	f.ackMode = false
	f.ackMu.Unlock()
}

func (f *Framer) ackEnabled() bool {
	f.ackMu.Lock()
	defer f.ackMu.Unlock()
	return f.ackMode
}

// readLoop consumes bytes one at a time and reconstructs frames with a
// strict state machine. Every inbound byte takes exactly one transition,
// including the two checksum digits, so packets split at any boundary
// ("half packets") reassemble correctly.
func (f *Framer) readLoop() {
	rbuf := make([]byte, 1)
	var body bytes.Buffer
	const (
		stIdle = iota
		stBody
		stSum1
		stSum2
	)
	state := stIdle
	var sumHi byte
	for {
		select {
		case <-f.closed:
			return
		default:
		}
		n, err := f.rw.Read(rbuf)
		if n > 0 {
			for _, b := range rbuf[:n] {
				switch state {
				case stIdle:
					switch b {
					case '$':
						body.Reset()
						state = stBody
					case 0x03:
						if !f.deliver(Frame{Kind: FrameInterrupt}) {
							return
						}
					case '+':
						f.postAck()
					case '-':
						// Unsolicited nack: nothing to retransmit.
					default:
						// resync: drop unexpected idle byte
					}
				case stBody:
					switch b {
					case '#':
						state = stSum1
					case '$':
						body.Reset() // resync
					default:
						if body.Len() >= f.cfg.MaxPacketBytes {
							if f.ackEnabled() {
								f.writeLocked([]byte{'-'})
							}
							body.Reset()
							state = stIdle
							continue
						}
						body.WriteByte(b)
					}
				case stSum1:
					sumHi = b
					state = stSum2
				case stSum2:
					state = stIdle
					sum, parseOK := parseHexByte([2]byte{sumHi, b})
					data := append([]byte(nil), body.Bytes()...)
					body.Reset()
					if !parseOK || !validChecksum(data, sum) {
						if f.ackEnabled() {
							f.writeLocked([]byte{'-'})
						}
						continue
					}
					if f.ackEnabled() {
						f.writeLocked([]byte{'+'})
					}
					if !f.deliver(Frame{Kind: FramePacket, Data: data}) {
						return
					}
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				select {
				case f.readErr <- io.EOF:
				default:
				}
			} else {
				select {
				case f.readErr <- err:
				default:
				}
			}
			return
		}
	}
}

func (f *Framer) deliver(fr Frame) bool {
	select {
	case f.frames <- fr:
		return true
	case <-f.closed:
		return false
	}
}

// writeLocked serialises ALL wire writes so reader-emitted acks never
// interleave with packet bytes written by SendPacket.
func (f *Framer) writeLocked(b []byte) {
	f.writeMu.Lock()
	_, _ = f.rw.Write(b)
	f.writeMu.Unlock()
}

func (f *Framer) postAck() {
	select {
	case f.ackSig <- struct{}{}:
	default: // a pending ack already queued; coalesce additional '+'
	}
}

// SendPacket frames body, writes it and waits for '+' (ack mode) with
// bounded retransmission. A late '+' from a previous attempt simply
// satisfies the current wait; timeout without ack triggers one resend.
func (f *Framer) SendPacket(ctx context.Context, body []byte) error {
	frame := EncodePacket(body)
	// All wire writes are serialised per attempt via writeLocked; the
	// mutex is not held while waiting for an ack so reader-emitted acks
	// can still be written concurrently.
	if !f.ackEnabled() {
		f.writeLocked(frame)
		return nil
	}

	// Drain a stale/late ack before starting a fresh exchange.
	select {
	case <-f.ackSig:
	default:
	}

	attempts := f.cfg.MaxRetransmit + 1
	for attempt := 0; attempt < attempts; attempt++ {
		f.writeLocked(frame)
		timer := f.cfg.Clock.NewTimer(f.cfg.AckTimeout)
		select {
		case <-f.ackSig:
			timer.Stop()
			return nil
		case <-timer.C():
			// timeout: retransmit
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-f.closed:
			timer.Stop()
			return io.ErrClosedPipe
		}
	}
	return &target.Error{Code: target.CodeTimeout, Op: "SendPacket",
		Detail: fmt.Sprintf("no acknowledgement after %d attempts", attempts)}
}

// RecvPacket returns the next packet or interrupt frame.
// RecvPacket returns the next packet or interrupt frame.
func (f *Framer) RecvPacket(ctx context.Context) (Frame, error) {
	return f.recv(ctx, nil)
}

// ErrIdleTimeout is returned when a receive waits longer than the
// configured idle duration without an inbound frame.
var ErrIdleTimeout = errors.New("idle session timeout")

// RecvPacketIdle behaves like RecvPacket but bounds how long it waits for
// the next frame. On timeout it returns ErrIdleTimeout without spawning or
// leaking a goroutine: the wait is a single select in this call.
func (f *Framer) RecvPacketIdle(ctx context.Context, idle time.Duration) (Frame, error) {
	if idle <= 0 {
		return f.recv(ctx, nil)
	}
	timer := f.cfg.Clock.NewTimer(idle)
	return f.recv(ctx, timer.C())
}

func (f *Framer) recv(ctx context.Context, idle <-chan time.Time) (Frame, error) {
	select {
	case fr := <-f.frames:
		return fr, nil
	case err := <-f.readErr:
		return Frame{}, err
	case <-idle:
		return Frame{}, ErrIdleTimeout
	case <-ctx.Done():
		return Frame{}, ctx.Err()
	case <-f.closed:
		return Frame{}, io.ErrClosedPipe
	}
}

// EncodePacket produces "$body#cc".
func EncodePacket(body []byte) []byte {
	out := make([]byte, 0, len(body)+4)
	out = append(out, '$')
	out = append(out, body...)
	out = append(out, '#')
	sum := Checksum(body)
	out = append(out, hexDigit(sum>>4), hexDigit(sum&0x0F))
	return out
}

// Checksum is the RSP sum of all body bytes modulo 256.
func Checksum(body []byte) byte {
	var sum uint
	for _, b := range body {
		sum += uint(b)
	}
	return byte(sum & 0xFF)
}

func validChecksum(body []byte, sum byte) bool {
	return Checksum(body) == sum
}

func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + n - 10
}

func parseHexByte(h [2]byte) (byte, bool) {
	hi, ok1 := fromHex(h[0])
	lo, ok2 := fromHex(h[1])
	if !ok1 || !ok2 {
		return 0, false
	}
	return hi<<4 | lo, true
}
