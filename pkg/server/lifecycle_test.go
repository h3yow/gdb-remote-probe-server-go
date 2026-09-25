package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

// A live server with a small idle timeout must converge a silent session
// to detached deterministically, without relying on the timeout value to
// assert correctness (a deadline bounds the test only).
func TestIdleTimeoutConverges(t *testing.T) {
	srv, _ := startServer(t, true)
	srv.cfg.IdleTimeout = 20 * time.Millisecond

	ln := startAccepting(t, srv)
	conn, err := dialTCP(ln)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cl := newClient(t, conn)
	if r := cl.cmd("?"); r[0] != 'S' {
		t.Fatalf("? = %q", r)
	}
	// Go silent: the server must detach by its configured idle deadline.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !srv.Manager().Active("target0") {
			return // deterministic terminal state
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("idle session did not converge to detached")
}

// Corrupt image files must be rejected at startup with a distinguishable
// code, never producing a half-initialised server.
func TestNewRejectsCorruptImage(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.img")
	p := target.NewProgram().Halt()
	img, err := target.BuildImage(p, 0, 0x100, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.WriteImage(good, img); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(good)

	cases := []struct {
		name string
		body []byte
		want target.Code
	}{
		{"truncated", raw[:8], target.CodeImageTooShort},
		{"bad-magic", func() []byte { b := append([]byte(nil), raw...); b[0] = 'Z'; return b }(),
			target.CodeBadMagic},
		{"bad-checksum", func() []byte { b := append([]byte(nil), raw...); b[len(b)-1] ^= 0xFF; return b }(),
			target.CodeBadChecksum},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".img")
			if err := os.WriteFile(path, tc.body, 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := New(Config{ImagePath: path, Log: discardLog{}})
			if target.CodeOf(err) != tc.want {
				t.Fatalf("want code %d, got %v", tc.want, err)
			}
		})
	}
}

// Kill over the wire resets the target and frees the session slot.
func TestKillPacketResetsTarget(t *testing.T) {
	srv, _ := startServer(t, false)
	c1, cl := dialPair(t, srv)
	defer c1.Close()
	cl.cmd("P1=2a000000") // set r1
	if r := cl.cmd("k"); r != "OK" {
		t.Fatalf("k = %q", r)
	}
	waitActiveFree(t, srv, false)
	c1.Close()

	c2, cl2 := dialPair(t, srv)
	defer c2.Close()
	if r := cl2.cmd("p1"); r != "00000000" {
		t.Fatalf("r1 after kill/reset = %q want 0", r)
	}
}

type discardLog struct{}

func (discardLog) Printf(string, ...interface{}) {}

var _ = context.Background
