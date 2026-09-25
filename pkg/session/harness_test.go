package session

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/clock"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/image"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/protocol"
	targetpkg "github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

// testLogger captures log lines for assertions on frames, states and rejects.
type testLogger struct {
	mu     sync.Mutex
	lines  []string
	t      *testing.T
	closed bool
}

func (l *testLogger) Printf(format string, args ...any) {
	line := strings.TrimSpace(fmt.Sprintf(format, args...))
	l.mu.Lock()
	l.lines = append(l.lines, line)
	tb := l.t
	closed := l.closed
	l.mu.Unlock()
	// Surface frames/states/rejections in test output; once the harness has
	// closed we only buffer, so late async session logs cannot panic on a
	// finished test.
	if tb != nil && !closed {
		tb.Logf("%s", line)
	}
}

func (l *testLogger) close() {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
}
func (l *testLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}
func (l *testLogger) Contains(sub string) bool { return strings.Contains(l.String(), sub) }
func (l *testLogger) Count(sub string) int     { return strings.Count(l.String(), sub) }

type harness struct {
	t        *testing.T
	tg       *targetpkg.Target
	srv      *Server
	client   *protocol.Link
	log      *testLogger
	srvConn  protocol.Conn
	cliConn  protocol.Conn
	serveErr chan error
}

func newHarness(t *testing.T, code []uint32, stripped bool, idle time.Duration) *harness {
	t.Helper()
	cb := make([]byte, len(code)*4)
	for i, w := range code {
		cb[i*4] = byte(w)
		cb[i*4+1] = byte(w >> 8)
		cb[i*4+2] = byte(w >> 16)
		cb[i*4+3] = byte(w >> 24)
	}
	b := image.NewBuilder().Entry(0x1000).
		Region(image.Region{Name: "flash", Addr: 0x1000, Data: cb, Perm: image.PermRead | image.PermExecute}).
		Region(image.Region{Name: "ram", Addr: 0x2000, Data: make([]byte, 32), Perm: image.PermRead | image.PermWrite}).
		Symbol(image.Symbol{Name: "main", Addr: 0x1000, Size: uint32(len(cb))}).
		Symbol(image.Symbol{Name: "g", Addr: 0x2000, Size: 4}).
		Stripped(stripped)
	raw, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	im, err := image.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := targetpkg.New(im)
	if err != nil {
		t.Fatal(err)
	}
	tg.SetInstructionBudget(0) // loops run until a trap or interrupt

	lg := &testLogger{t: t}
	clk := clock.NewRealClock()
	opts := protocol.LinkOptions{AckTimeout: 25 * time.Millisecond, MaxRetries: 5, Clock: clk}
	cfg := Config{StrictCaps: false, IdleTimeout: idle, Link: opts, Clock: clk, Logger: lg}
	srv := New(tg, cfg)

	srvConn, cliConn := protocol.NewPipe()
	client := protocol.NewLink(cliConn, opts)
	h := &harness{
		t: t, tg: tg, srv: srv, client: client, log: lg,
		srvConn:  srvConn,
		cliConn:  cliConn,
		serveErr: make(chan error, 1),
	}
	go func() { h.serveErr <- srv.ServeConn(srvConn) }()
	return h
}

func (h *harness) close() {
	h.log.close()
	_ = h.client.Close()
	_ = h.srvConn.Close()
	_ = h.srv.Close()
}

// cmd performs one request/response round trip.
func (h *harness) cmd(req string) string {
	h.t.Helper()
	if err := h.client.Send([]byte(req)); err != nil {
		h.t.Fatalf("send %q: %v\nSERVER LOG:\n%s", req, err, h.log)
	}
	body, err := h.client.Recv()
	if err != nil {
		h.t.Fatalf("recv for %q: %v\nSERVER LOG:\n%s", req, err, h.log)
	}
	return string(body)
}

// negotiate sends qSupported.
func (h *harness) negotiate(features string) string {
	return h.cmd("qSupported:" + features)
}

func mustPrefix(t *testing.T, got, want string) {
	t.Helper()
	if !strings.HasPrefix(got, want) {
		t.Fatalf("reply %q want prefix %q", got, want)
	}
}

func (h *harness) targetBreakpoints() []targetpkg.BreakpointInfo { return h.tg.Breakpoints() }
