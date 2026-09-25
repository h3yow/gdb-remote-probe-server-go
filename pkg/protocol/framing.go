package protocol

import (
	"context"
	"io"
	"time"
)

// Frame is one inbound protocol element delivered by the demultiplexer.
type FrameKind int

const (
	FramePacket FrameKind = iota
	FrameInterrupt // raw 0x03 byte
)

// Frame is one inbound protocol element.
type Frame struct {
	Kind FrameKind
	Data []byte // packet body without $, #, checksum for FramePacket
}

// FramerConfig tunes framing behaviour.
type FramerConfig struct {
	AckTimeout     time.Duration
	MaxRetransmit  int
	MaxPacketBytes int
	Clock          Clock
}

// DefaultFramerConfig returns sensible production defaults.
func DefaultFramerConfig() FramerConfig { return FramerConfig{} }

// Framer implements RSP framing: '$' packet framing with two-digit hex
// checksum, '+'/'-' acknowledgements, retransmission, duplicate detection
// and raw 0x03 interrupt bytes. A single reader goroutine demultiplexes
// the byte stream so acknowledgements interleaved with packets never
// corrupt state.
type Framer struct {
	cfg FramerConfig
	rw  io.ReadWriter

	packets chan Frame
	acks    chan struct{}
	nacks   chan struct{}
	readErr chan error

	ackMode bool // false after QStartNoAckMode handshake

	// retransmission/duplicate state
	lastOut   []byte
	outSeqOK  bool
	inLast    string
	ackClosed bool
}

// NewFramer starts the reader loop for the given transport.
func NewFramer(rw io.ReadWriter, cfg FramerConfig) *Framer { return nil }

// Close stops the reader goroutine and releases resources.
func (f *Framer) Close() error { return nil }

// SetNoAckMode disables outbound acknowledgements and inbound ack waits.
func (f *Framer) SetNoAckMode() {}

// SendPacket frames body, writes it and waits for '+' (ack mode) with
// bounded retransmission. It is safe to call from a single sender
// goroutine only (the server command loop).
func (f *Framer) SendPacket(ctx context.Context, body []byte) error { return nil }

// RecvPacket returns the next packet or interrupt frame.
func (f *Framer) RecvPacket(ctx context.Context) (Frame, error) { return Frame{}, nil }

// Frame helpers exported for tests.

func EncodePacket(body []byte) []byte { return nil }
func Checksum(body []byte) byte      { return 0 }
func validChecksum(body []byte, sum byte) bool { return false }
