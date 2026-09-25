package protocol

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncodeChecksum(t *testing.T) {
	// gdb-style example: empty body -> $#00
	if got := EncodeFrame(nil); !bytes.Equal(got, []byte("$#00")) {
		t.Fatalf("empty frame: %q", got)
	}
	if got := EncodeFrame([]byte("g")); string(got) != "$g#67" {
		t.Fatalf("g frame: %q", got)
	}
}

func TestDecodeSimple(t *testing.T) {
	d := NewDecoder()
	r := d.Push(EncodeFrame([]byte("qSupported")))
	if len(r.Frames) != 1 || string(r.Frames[0]) != "qSupported" {
		t.Fatalf("frames=%x errs=%v ctrls=%v", r.Frames, r.Errors, r.Control)
	}
}

func TestDecodeHalfPackets(t *testing.T) {
	full := EncodeFrame([]byte("m1000,4"))
	d := NewDecoder()
	var got [][]byte
	for _, cut := range []int{1, 3, 7, 2, 1} {
		if cut > len(full) {
			break
		}
		r := d.Push(full[:cut])
		full = full[cut:]
		got = append(got, r.Frames...)
	}
	r := d.Push(full)
	got = append(got, r.Frames...)
	if len(got) != 1 || string(got[0]) != "m1000,4" {
		t.Fatalf("reassembly got %x", got)
	}
}

func TestDecodeMultipleAndControl(t *testing.T) {
	d := NewDecoder()
	stream := []byte{}
	stream = append(stream, '+')
	stream = append(stream, EncodeFrame([]byte("g"))...)
	stream = append(stream, '-')
	stream = append(stream, EncodeFrame([]byte("P1=05"))...)
	stream = append(stream, ByteCtrlC)
	r := d.Push(stream)
	if len(r.Frames) != 2 || string(r.Frames[0]) != "g" || string(r.Frames[1]) != "P1=05" {
		t.Fatalf("frames: %x", r.Frames)
	}
	if len(r.Control) != 3 || r.Control[0] != EventAck ||
		r.Control[1] != EventNack || r.Control[2] != EventCtrlC {
		t.Fatalf("ctrls: %v", r.Control)
	}
}

func TestDecodeChecksumError(t *testing.T) {
	f := EncodeFrame([]byte("g"))
	f[len(f)-1] = '0' // corrupt checksum
	d := NewDecoder()
	r := d.Push(f)
	if len(r.Frames) != 0 || len(r.Errors) != 1 || !errors.Is(r.Errors[0], ErrChecksum) {
		t.Fatalf("want one checksum error, frames=%x errs=%v", r.Frames, r.Errors)
	}
	// decoder keeps working: next valid frame still decoded
	r2 := d.Push(EncodeFrame([]byte("ok")))
	if len(r2.Frames) != 1 || string(r2.Frames[0]) != "ok" {
		t.Fatalf("recovery failed: %x %v", r2.Frames, r2.Errors)
	}
}

func TestDecodeNoiseAndBadTrailer(t *testing.T) {
	d := NewDecoder()
	// garbage then a restarted frame
	r := d.Push([]byte("garbage$abc$m1000,4#"))
	if len(r.Frames) != 0 || len(r.Errors) != 0 {
		t.Fatalf("partial unexpectedly completed: %+v", r)
	}
	// first nibble valid, second not a hex digit -> malformed trailer
	r = d.Push([]byte("6z"))
	if len(r.Errors) != 1 || !errors.Is(r.Errors[0], ErrFrameBad) {
		t.Fatalf("want frame-bad, got %v", r.Errors)
	}
	// resync
	r = d.Push(EncodeFrame([]byte("z0")))
	if len(r.Frames) != 1 || string(r.Frames[0]) != "z0" {
		t.Fatalf("resync frames=%x errs=%v", r.Frames, r.Errors)
	}
}
