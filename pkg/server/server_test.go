package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/protocol"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

type bufLog struct {
	t  *testing.T
	mu sync.Mutex
	sb strings.Builder
}

func (b *bufLog) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}

func (b *bufLog) Printf(format string, args ...interface{}) {
	b.mu.Lock()
	b.sb.WriteString("[log] ")
	b.sb.WriteString(strings.TrimSpace(fmt.Sprintf(format, args...)))
	b.sb.WriteByte('\n')
	b.mu.Unlock()
	b.t.Logf(format, args...)
}

// client wraps a net.Conn with an RSP framer. A single reader goroutine
// feeds a queue so both the async 'c' waiter and synchronous commands can
// coexist without stealing each other's frames.
type client struct {
	t  *testing.T
	c  net.Conn
	fr *protocol.Framer

	qmu  sync.Mutex
	cond *sync.Cond
	q    []string
	err  error
}

func (cl *client) reader() {
	for {
		f, err := cl.fr.RecvPacket(context.Background())
		cl.qmu.Lock()
		if err != nil {
			cl.err = err
		} else if f.Kind == protocol.FramePacket {
			cl.q = append(cl.q, string(f.Data))
		}
		cl.cond.Broadcast()
		cl.qmu.Unlock()
		if err != nil {
			return
		}
	}
}

// nextReply returns the next queued packet reply or "" when the transport
// has ended.
func (cl *client) nextReply() string {
	cl.qmu.Lock()
	defer cl.qmu.Unlock()
	for len(cl.q) == 0 && cl.err == nil {
		cl.cond.Wait()
	}
	if len(cl.q) > 0 {
		r := cl.q[0]
		cl.q = cl.q[1:]
		return r
	}
	return ""
}

func newClient(t *testing.T, c net.Conn) *client {
	cl := &client{t: t, c: c, fr: protocol.NewFramer(c, protocol.DefaultFramerConfig())}
	cl.cond = sync.NewCond(&cl.qmu)
	go cl.reader()
	return cl
}

func (cl *client) close() { _ = cl.c.Close() }

func (cl *client) sendRaw(b []byte) {
	if _, err := cl.c.Write(b); err != nil {
		cl.t.Fatalf("raw write: %v", err)
	}
}

func (cl *client) cmd(body string) string {
	if err := cl.fr.SendPacket(context.Background(), []byte(body)); err != nil {
		cl.t.Fatalf("send %q: %v", body, err)
	}
	return cl.nextReply()
}

// cmdAsync sends a packet and returns a channel completed with the next
// packet reply.
func (cl *client) cmdAsync(body string) <-chan string {
	out := make(chan string, 1)
	if err := cl.fr.SendPacket(context.Background(), []byte(body)); err != nil {
		cl.t.Fatalf("send %q: %v", body, err)
	}
	go func() { out <- cl.nextReply() }()
	return out
}

func (cl *client) noAck() { cl.fr.SetNoAckMode() }

func (cl *client) interrupt() {
	if _, err := cl.c.Write([]byte{0x03}); err != nil {
		cl.t.Fatalf("interrupt: %v", err)
	}
}

func (cl *client) recvRawPacket() []byte {
	cl.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var buf bytes.Buffer
	one := make([]byte, 1)
	// wait for a '$' frame
	for {
		n, err := cl.c.Read(one)
		if n > 0 && one[0] != '+' {
			buf.WriteByte(one[0])
			if one[0] == '$' {
				break
			}
		}
		if err != nil {
			cl.t.Fatalf("recvRaw start: %v", err)
		}
	}
	// read until '#' plus two checksum digits
	for buf.Len() < 4 || buf.Bytes()[buf.Len()-3] != '#' {
		n, err := cl.c.Read(one)
		if n > 0 {
			buf.Write(one[:n])
		}
		if err != nil {
			cl.t.Fatalf("recvRaw body: %v", err)
		}
	}
	return buf.Bytes()
}

func startServer(t *testing.T, stripped bool) (*Server, *bufLog) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.img")
	p := target.NewProgram().
		Movi(target.RegR0, 7).
		St(0x20, target.RegR0).
		Label("loop").
		Jmp("loop")
	img, err := target.BuildImage(p, 0, 0x20, []byte{0, 0, 0, 0}, stripped)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.WriteImage(path, img); err != nil {
		t.Fatal(err)
	}
	lg := &bufLog{t: t}
	srv, err := New(Config{ImagePath: path, Listen: "127.0.0.1:0", Log: lg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv, lg
}

func startAccepting(t *testing.T, srv *Server) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConn(context.Background(), c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func dialTCP(ln net.Listener) (net.Conn, error) {
	return net.Dial("tcp", ln.Addr().String())
}

func dialPair(t *testing.T, srv *Server) (net.Conn, *client) {
	ln := startAccepting(t, srv)
	clConn, err := dialTCP(ln)
	if err != nil {
		t.Fatal(err)
	}
	return clConn, newClient(t, clConn)
}

func waitActiveFree(t *testing.T, srv *Server, want bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Manager().Active("target0") == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active state did not converge to %v", want)
}

func waitLogContains(t *testing.T, lg *bufLog, sub string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(lg.String(), sub) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("log never contained %q; log:\n%s", sub, lg.String())
}

func waitRunning(t *testing.T, srv *Server, want bool) {
	t.Helper()
	tg := srv.Manager().Target("target0")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if tg.IsRunning() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("target running did not converge to %v", want)
}

func TestEndToEndRegsMemBreakpoints(t *testing.T) {
	srv, lg := startServer(t, true) // stripped image
	conn, cl := dialPair(t, srv)
	defer conn.Close()

	if r := cl.cmd("qSupported:swbreak+"); !strings.Contains(r, "swbreak+") {
		t.Fatalf("qSupported = %q", r)
	}
	if r := cl.cmd("Z0,4,0"); r != "OK" {
		t.Fatalf("set bp = %q", r)
	}
	// continue hits the breakpoint at 0x04
	cReply := cl.cmdAsync("c")
	if got := <-cReply; got != "S05" {
		t.Fatalf("stop reply = %q want S05", got)
	}
	// instruction at pc: st 0x20,r0 => 05 00 20 00
	if r := cl.cmd("m4,4"); r != "05002000" {
		t.Fatalf("m4,4 = %q", r)
	}
	// read-only write into R-X .text on a stripped image
	if r := cl.cmd("M4,4:00000000"); r != "E08" {
		t.Fatalf("ro write = %q want E08", r)
	}
	// breakpoint limit: one bp installed, cap is 4; misaligned + non-exec
	if r := cl.cmd("Z0,5,0"); r != "E0a" {
		t.Fatalf("misaligned = %q want E0a", r)
	}
	if r := cl.cmd("Z0,20,0"); r != "E09" {
		t.Fatalf("not-exec = %q want E09", r)
	}
	if r := cl.cmd("z0,4,0"); r != "OK" {
		t.Fatalf("clear = %q", r)
	}
	// Back-to-back identical frames are protocol duplicates; prove target
	// clear idempotency through a set/clear cycle instead.
	if r := cl.cmd("Z0,4,0"); r != "OK" {
		t.Fatalf("re-set after clear = %q", r)
	}
	if r := cl.cmd("z0,4,0"); r != "OK" {
		t.Fatalf("second clear = %q", r)
	}
	if !strings.Contains(lg.String(), "dispatch") {
		t.Fatal("log must include packet records")
	}
}

func TestContinueInterruptAndRunningConflict(t *testing.T) {
	srv, lg := startServer(t, true)
	conn, cl := dialPair(t, srv)
	defer conn.Close()

	cReply := cl.cmdAsync("c")
	waitRunning(t, srv, true)

	// A command against a running target is a conflict: the server must
	// reject it instead of executing. We observe the rejection in the
	// server log; the conflicting client request is intentionally not
	// answered because the in-flight 'c' owns the single reply channel.
	if err := cl.fr.SendPacket(context.Background(), []byte("m0,4")); err != nil {
		t.Fatal(err)
	}
	waitLogContains(t, lg, "reject running packet")
	// interrupt: the blocked 'c' then completes with S02. The E0f
	// rejection is not produced (conflict rejected, not executed).
	cl.interrupt()
	if got := <-cReply; got != "S02" {
		t.Fatalf("interrupt stop = %q want S02", got)
	}
	waitRunning(t, srv, false)
}

func TestMalformedAndBadChecksum(t *testing.T) {
	srv, _ := startServer(t, true)
	// Dedicated raw connection: a framer and a raw reader must never share
	// one transport.
	ln := startAccepting(t, srv)
	clConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clConn.Close()
	raw := newRaw(t, clConn)

	// Corrupt frame must draw '-' and never be delivered.
	raw.write([]byte("$g#00"))
	got := raw.readUntilAckOrNack()
	if !bytes.Contains(got, []byte("-")) {
		t.Fatalf("want '-' nack for bad checksum, got %q", got)
	}
	// Half packet split at any boundary: first part, then the rest; a
	// valid '+' must follow.
	raw.write([]byte("$g#6"))
	raw.write([]byte("7"))
	got = raw.readUntilAckOrNack()
	if !bytes.Contains(got, []byte("+")) {
		t.Fatalf("half packet want '+' after completion, got %q", got)
	}
}

func TestUnknownPacketAfterRecovery(t *testing.T) {
	srv, _ := startServer(t, true)
	conn, cl := dialPair(t, srv)
	defer conn.Close()
	if r := cl.cmd("g"); len(r) != target.RegN*8 {
		t.Fatalf("g = %q", r)
	}
	if r := cl.cmd("zzz"); r != "E14" {
		t.Fatalf("malformed = %q want E14", r)
	}
}

func TestSecondSessionRejected(t *testing.T) {
	srv, lg := startServer(t, false)
	c1, cl1 := dialPair(t, srv)
	defer c1.Close()
	if r := cl1.cmd("?"); r != "S00" {
		t.Fatalf("first session ? = %q", r)
	}

	ln := startAccepting(t, srv)
	clConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clConn.Close()
	_ = clConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := clConn.Read(buf)
	if err != nil {
		t.Fatalf("second conn read: %v", err)
	}
	if !bytes.Contains(buf[:n], []byte("E12")) {
		t.Fatalf("second session want E12, got %q", buf[:n])
	}
	if !strings.Contains(lg.String(), "session rejected") {
		t.Fatal("rejection must be logged with reason")
	}

	// detach frees slot
	if r := cl1.cmd("D"); r != "OK" {
		t.Fatalf("detach = %q", r)
	}
	waitActiveFree(t, srv, false)
	c1.Close()

	c3, cl3 := dialPair(t, srv)
	defer c3.Close()
	if r := cl3.cmd("?"); !strings.HasPrefix(r, "S") {
		t.Fatalf("reconnect after detach = %q", r)
	}
}

func TestDisconnectWhileRunningConverges(t *testing.T) {
	srv, lg := startServer(t, true)
	conn, cl := dialPair(t, srv)
	_ = cl.cmdAsync("c")
	waitRunning(t, srv, true)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		tg := srv.Manager().Target("target0")
		if !srv.Manager().Active("target0") && tg != nil && !tg.IsRunning() {
			if !strings.Contains(lg.String(), "converge detach") {
				t.Fatalf("log missing convergence record: %s", lg.String())
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("target did not converge to stopped+detached after disconnect")
}

func TestSymbolsAvailableWhenNotStripped(t *testing.T) {
	srv, _ := startServer(t, false)
	sym, err := srv.LoadedImage().LookupSymbol("loop")
	if err != nil {
		t.Fatalf("unstripped symbols: %v", err)
	}
	if sym.Addr != 2*4 {
		t.Fatalf("loop = %#x", sym.Addr)
	}
}

// rawClient performs byte-level I/O on an existing net.Conn for malformed
// input tests, bypassing the RSP framer.
type rawClient struct {
	t *testing.T
	c net.Conn
}

func newRaw(t *testing.T, c net.Conn) *rawClient { return &rawClient{t: t, c: c} }

func (r *rawClient) write(b []byte) {
	if _, err := r.c.Write(b); err != nil {
		r.t.Fatalf("raw write: %v", err)
	}
}

func (r *rawClient) readUntilAckOrNack() []byte {
	_ = r.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 0, 4)
	one := make([]byte, 1)
	for {
		n, err := r.c.Read(one)
		if n > 0 {
			buf = append(buf, one[0])
			if bytes.ContainsAny(one[:n], "+-") {
				return buf
			}
		}
		if err != nil {
			return buf
		}
	}
}
