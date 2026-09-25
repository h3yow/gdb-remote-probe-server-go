package protocol

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

// Session-style rapid alternating exchanges (real clock, event driven).
func TestMultiExchangeRapid(t *testing.T) {
	ca, cb := NewPipe()
	a := NewLink(ca, LinkOptions{AckTimeout: 25 * time.Millisecond, MaxRetries: 5})
	b := NewLink(cb, LinkOptions{AckTimeout: 25 * time.Millisecond, MaxRetries: 5})
	t.Cleanup(func() { a.Close(); b.Close() })
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		for i := 0; i < 20; i++ {
			body, err := b.Recv()
			if err != nil {
				return
			}
			if err := b.Send(append([]byte("reply:"), body...)); err != nil {
				return
			}
		}
	}()
	for i := 0; i < 20; i++ {
		req := []byte(fmt.Sprintf("cmd%d", i))
		if err := a.Send(req); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		rep, err := a.Recv()
		if err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
		if want := "reply:cmd" + strconv.Itoa(i); string(rep) != want {
			t.Fatalf("reply %d: got %q want %q", i, rep, want)
		}
	}
	<-srvDone
}
