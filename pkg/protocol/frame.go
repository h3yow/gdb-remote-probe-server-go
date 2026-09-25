// Package protocol implements the serial debug wire protocol: framing
// ($...#cc), checksum validation, +/- acknowledgements and retransmission,
// over a byte-oriented transport that tests can impair.
//
// Wire layout:
//
//	packet: '$' body '#' hexHi hexLo          (hex is lowercase)
//	control: '+' ack, '-' nak, 0x03 interrupt
//
// The Decoder reassembles packets from arbitrary byte chunks (half packets),
// recovers from framing noise and reports checksum failures per frame without
// losing subsequent data.
package protocol

import (
	"errors"
	"fmt"
)

// Frame control bytes.
const (
	ByteFrameStart byte = '$'
	ByteFrameEnd   byte = '#'
	ByteAck        byte = '+'
	ByteNack       byte = '-'
	ByteCtrlC      byte = 0x03
)

// Errors distinguishable by callers.
var (
	ErrChecksum = errors.New("protocol: checksum mismatch")
	ErrFrameBad = errors.New("protocol: malformed frame")
	ErrTimeout  = errors.New("protocol: link timeout")
	ErrClosed   = errors.New("protocol: link closed")
	ErrRejected = errors.New("protocol: connection rejected")
)

// Checksum is the arithmetic sum of body bytes modulo 256.
func Checksum(body []byte) uint8 {
	var sum uint8
	for _, b := range body {
		sum += b
	}
	return sum
}

// EncodeFrame returns "$body#cc".
func EncodeFrame(body []byte) []byte {
	out := make([]byte, 0, len(body)+4)
	out = append(out, ByteFrameStart)
	out = append(out, body...)
	out = append(out, ByteFrameEnd)
	cs := Checksum(body)
	const hex = "0123456789abcdef"
	out = append(out, hex[cs>>4], hex[cs&0xF])
	return out
}

// ControlEvent is a non-packet control byte observed by the decoder.
type ControlEvent byte

// Event constants.
const (
	EventAck   = ControlEvent(ByteAck)
	EventNack  = ControlEvent(ByteNack)
	EventCtrlC = ControlEvent(ByteCtrlC)
)

// PushResult carries one Push call's observations in wire order.
type PushResult struct {
	Frames  [][]byte
	Errors  []error
	Control []ControlEvent
}

// decoder states.
const (
	stIdle = iota
	stBody
	stCSHi
	stCSLo
)

// Decoder incrementally reassembles frames from a byte stream. Bytes outside a
// frame are classified as control events or ignored noise; a frame with a
// truncated/invalid trailer is reported as ErrFrameBad and the decoder
// resynchronizes at the next '$'.
type Decoder struct {
	state int
	body  []byte
	csHi  byte
	csLo  byte
	res   PushResult
}

// NewDecoder constructs a stream decoder.
func NewDecoder() *Decoder { return &Decoder{} }

// Push feeds arbitrary bytes and returns completed frames, per-frame errors
// (checksum mismatch, malformed trailer) and control events in wire order.
// Returned frame slices are copies owned by the caller.
func (d *Decoder) Push(p []byte) PushResult {
	d.res = PushResult{}
	for _, b := range p {
		d.pushByte(b)
	}
	res := d.res
	d.res = PushResult{}
	return res
}

func (d *Decoder) pushByte(b byte) {
	switch d.state {
	case stIdle:
		switch b {
		case ByteFrameStart:
			d.state = stBody
			d.body = d.body[:0]
		case ByteAck, ByteNack, ByteCtrlC:
			d.res.Control = append(d.res.Control, ControlEvent(b))
		}
	case stBody:
		switch b {
		case ByteFrameStart:
			// Restart: previous frame had no terminator; treat its bytes as noise.
			d.body = d.body[:0]
		case ByteFrameEnd:
			d.state = stCSHi
		default:
			d.body = append(d.body, b)
		}
	case stCSHi:
		d.csHi = b
		d.state = stCSLo
	case stCSLo:
		d.csLo = b
		d.state = stIdle
		hi, okHi := fromHex(d.csHi)
		lo, okLo := fromHex(d.csLo)
		if !okHi || !okLo {
			d.res.Errors = append(d.res.Errors,
				fmt.Errorf("%w: bad checksum digits %q%q", ErrFrameBad, d.csHi, d.csLo))
			return
		}
		want := hi<<4 | lo
		got := Checksum(d.body)
		body := append([]byte(nil), d.body...)
		if got != want {
			d.res.Errors = append(d.res.Errors,
				fmt.Errorf("%w: body=%q got=%02x want=%02x", ErrChecksum, body, got, want))
		} else {
			d.res.Frames = append(d.res.Frames, body)
		}
	}
}

func fromHex(b byte) (uint8, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}
