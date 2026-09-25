package protocol

import (
	"bytes"
	"testing"
)

func TestPipeMultiWrites(t *testing.T) {
	ca, cb := NewPipe()
	messages := [][]byte{
		EncodeFrame([]byte("cmd")),
		[]byte("+"),
		EncodeFrame([]byte("reply:cmd")),
		[]byte("+"),
		EncodeFrame([]byte("cmd")),
	}
	for _, m := range messages {
		if _, err := ca.Write(m); err != nil {
			t.Fatal(err)
		}
	}
	// read everything from cb
	var got bytes.Buffer
	buf := make([]byte, 256)
	for i := 0; i < len(messages); i++ {
		n, err := cb.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got.Write(buf[:n])
	}
	want := bytes.Join(messages, nil)
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("pipe lost/reordered bytes:\n got %q\nwant %q", got.Bytes(), want)
	}
}
