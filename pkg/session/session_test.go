package session

import (
	"errors"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/clock"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/image"
	"strings"
	"testing"
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/protocol"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

func loopProgram() []uint32 {
	const codeAddr = uint32(0x1000)
	return []uint32{
		target.Encode(target.OpMOVI, 1, 0, 1),
		target.Encode(target.OpADDI, 1, 0, 1),
		target.Encode(target.OpJMP, 0, 0, uint16(codeAddr+4)), // loop adding
	}
}

func TestNegotiationAndBasicFlow(t *testing.T) {
	h := newHarness(t, loopProgram(), false, 0)
	defer h.close()

	rep := h.negotiate("swbreak+;hwbreak+;qXfer:memory-map+;PacketSize=400")
	if !strings.Contains(rep, "hwbreak+") || !strings.Contains(rep, "swbreak+") {
		t.Fatalf("negotiation reply missing features: %q", rep)
	}
	if !strings.Contains(rep, "PacketSize=400") {
		t.Fatalf("packet size not reflected: %q", rep)
	}

	if rep := h.cmd("?"); !strings.HasPrefix(rep, "S") {
		t.Fatalf("halt reason: %q", rep)
	}
	// registers initially zero except PC=0x1000
	regs := h.cmd("g")
	want := strings.Repeat("00000000", 15) + "00001000"
	if regs != want {
		t.Fatalf("regs:\n got %s\nwant %s", regs, want)
	}
	// read PC register (r15)
	if rep := h.cmd("pf"); rep != "00001000" {
		t.Fatalf("p15: %q", rep)
	}
}

func TestNegotiationRejectsWrongFirstPacket(t *testing.T) {
	h := newHarness(t, loopProgram(), false, 0)
	defer h.close()
	// Send something other than qSupported first.
	if err := h.client.Send([]byte("g")); err != nil {
		t.Fatal(err)
	}
	body, err := h.client.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "E03" {
		t.Fatalf("want E03 reject, got %q", body)
	}
	if err := <-h.serveErr; !errors.Is(err, ErrCapabilityRejected) {
		t.Fatalf("serve err: %v", err)
	}
	if !h.log.Contains("rejected") {
		t.Fatalf("log missing rejection: %s", h.log)
	}
}

func TestConcurrentSessionRejected(t *testing.T) {
	h := newHarness(t, loopProgram(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	second, cli2 := protocol.NewPipe()
	_ = cli2
	err := h.srv.ServeConn(second)
	if !errors.Is(err, ErrSessionBusy) {
		t.Fatalf("second session: %v", err)
	}
	if !h.srv.Active() {
		t.Fatal("first session must stay active")
	}
	if !h.log.Contains("session: opened") {
		t.Fatal("missing open log")
	}
}

func TestMemoryAndRegConsistency(t *testing.T) {
	h := newHarness(t, loopProgram(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	// write RAM via hex M command
	if rep := h.cmd("M2000,4:0a000000"); rep != "OK" {
		t.Fatalf("M write: %q", rep)
	}
	if rep := h.cmd("m2000,4"); rep != "0a000000" {
		t.Fatalf("m read: %q", rep)
	}
	// binary X write
	payload := make([]byte, 4)
	payload[0], payload[1], payload[2], payload[3] = 1, 2, 3, 4
	if err := h.client.Send(append([]byte("X2000,4:"), payload...)); err != nil {
		t.Fatal(err)
	}
	if rep := mustRecv(h); rep != "OK" {
		t.Fatalf("X write: %q", rep)
	}
	if rep := h.cmd("m2000,4"); rep != "01020304" {
		t.Fatalf("X readback: %q", rep)
	}
	// read-only flash write -> E24
	if rep := h.cmd("M1000,4:00000000"); rep != "E24" {
		t.Fatalf("flash write: %q", rep)
	}
	// out of range -> E23
	if rep := h.cmd("m9000,4"); rep != "E23" {
		t.Fatalf("oob read: %q", rep)
	}
	// unaligned -> E22
	if rep := h.cmd("m2001,4"); rep != "E22" {
		t.Fatalf("unaligned: %q", rep)
	}
	// register write then read
	if rep := h.cmd("P1=0000002a"); rep != "OK" {
		t.Fatalf("P write: %q", rep)
	}
	if rep := h.cmd("p1"); rep != "0000002a" {
		t.Fatalf("p read: %q", rep)
	}
	// r0 read-only -> E21
	if rep := h.cmd("P0=00000001"); rep != "E21" {
		t.Fatalf("r0 write: %q", rep)
	}
}

func mustRecv(h *harness) string {
	b, err := h.client.Recv()
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

func TestBreakpointBoundaries(t *testing.T) {
	code := make([]uint32, 6)
	for i := range code {
		code[i] = target.Encode(target.OpMOVI, 1, 0, uint16(i))
	}
	h := newHarness(t, code, false, 0)
	defer h.close()

	h.negotiate("hwbreak+")

	for _, a := range []uint32{0x1000, 0x1004, 0x1008, 0x100c} {
		if rep := h.cmd(sprintfBP(a)); rep != "OK" {
			t.Fatalf("set %#x: %q", a, rep)
		}
	}
	// repeat set is idempotent (still OK, no new slot)
	if rep := h.cmd("Z1,1000,4"); rep != "OK" {
		t.Fatalf("idempotent set: %q", rep)
	}
	// fifth unique -> E30 limit
	if rep := h.cmd("Z1,1010,4"); rep != "E30" {
		t.Fatalf("bp limit: %q", rep)
	}
	// non-code -> E33
	if rep := h.cmd("Z1,2000,4"); rep != "E33" {
		t.Fatalf("bp non-code: %q", rep)
	}
	// unaligned -> E22
	if rep := h.cmd("Z1,1001,4"); rep != "E22" {
		t.Fatalf("bp unaligned: %q", rep)
	}
	// clear then re-set works
	if rep := h.cmd("z1,1000,4"); rep != "OK" {
		t.Fatalf("clear: %q", rep)
	}
	if rep := h.cmd("Z1,1010,4"); rep != "OK" {
		t.Fatalf("reset after clear: %q", rep)
	}
	// clear absent -> E32
	if rep := h.cmd("z1,1000,4"); rep != "E32" {
		t.Fatalf("clear absent: %q", rep)
	}
}

func sprintfBP(a uint32) string {
	return "Z1," + toHex(a) + ",4"
}
func toHex(a uint32) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = digits[a&0xF]
		a >>= 4
	}
	return string(out)
}

func TestStepContinueBreakpoint(t *testing.T) {
	// 0x1000 r1=1 ; 0x1004 r1+=1 ; 0x1008 jmp 0x1004 (incrementing loop)
	code := []uint32{
		target.Encode(target.OpMOVI, 1, 0, 1),
		target.Encode(target.OpADDI, 1, 0, 1),
		target.Encode(target.OpJMP, 0, 0, uint16(0x1004)),
	}
	h := newHarness(t, code, false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	// Run straight to a breakpoint placed at the loop head 0x1004. The MOVI at
	// 0x1000 executes first (r1 becomes 1), then the breakpoint traps before
	// the ADDI at 0x1004 runs.
	if rep := h.cmd("Z1,1004,4"); rep != "OK" {
		t.Fatalf("set bp: %q", rep)
	}
	if rep := h.cmd("c"); !strings.HasPrefix(rep, "S05") {
		t.Fatalf("continue to bp: %q", rep)
	}
	if rep := h.cmd("p1"); rep != "00000001" {
		t.Fatalf("r1 at first bp hit: %q", rep)
	}
	// Continue: ADDI runs (r1=2), JMP loops back and the bp hits again.
	if rep := h.cmd("c"); !strings.HasPrefix(rep, "S05") {
		t.Fatalf("continue loop: %q", rep)
	}
	if rep := h.cmd("p1"); rep != "00000002" {
		t.Fatalf("r1 after one loop: %q", rep)
	}
	// Another iteration: r1=3 and the breakpoint hit count is now 3.
	if rep := h.cmd("c"); !strings.HasPrefix(rep, "S05") {
		t.Fatalf("continue loop2: %q", rep)
	}
	if rep := h.cmd("p1"); rep != "00000003" {
		t.Fatalf("r1 after two loops: %q", rep)
	}
	var hits uint64
	for _, b := range h.targetBreakpoints() {
		if b.Addr == 0x1004 {
			hits = b.Hits
		}
	}
	if hits != 3 {
		t.Fatalf("bp hits=%d want 3", hits)
	}
}

func TestRunningCommandRejectedAndInterrupt(t *testing.T) {
	h := newHarness(t, []uint32{
		target.Encode(target.OpJMP, 0, 0, uint16(0x1000)), // infinite loop
	}, false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	// One goroutine is the sole client reader; it hands each reply to the
	// test so Send ordering and reads never race on the link's frame stream.
	replies := make(chan string, 4)
	go func() {
		for {
			b, err := h.client.Recv()
			if err != nil {
				return
			}
			replies <- string(b)
		}
	}()
	send := func(req string) {
		if err := h.client.Send([]byte(req)); err != nil {
			t.Fatal(err)
		}
	}
	recvReply := func(label string) string {
		select {
		case r := <-replies:
			return r
		case <-time.After(2 * time.Second):
			t.Fatalf("no reply for %s\nLOG:\n%s", label, h.log)
			return ""
		}
	}

	send("c")
	// Wait deterministically until the server logs "running".
	waitFor(h, "state -> running")

	// A register write while running must be rejected E10 and not mutate state.
	send("P1=0000007b")
	if rep := recvReply("P1"); rep != "E10" {
		t.Fatalf("running write: %q", rep)
	}
	// Interrupt via ctrl-c; the stop reply belongs to the earlier "c".
	if err := h.client.SendCtrl(protocol.ByteCtrlC); err != nil {
		t.Fatal(err)
	}
	if rep := recvReply("ctrlc"); !strings.HasPrefix(rep, "S") {
		t.Fatalf("interrupt stop: %q", rep)
	}
	// After interrupt, commands work again and r1 is unchanged.
	send("p1")
	if rep := recvReply("p1"); rep != "00000000" {
		t.Fatalf("r1 mutated by rejected running write: %q", rep)
	}
	if !h.log.Contains("halted(pause)") {
		t.Fatalf("missing pause state: %s", h.log)
	}
}

func TestStrippedImageSymbols(t *testing.T) {
	h := newHarness(t, loopProgram(), true, 0)
	defer h.close()
	h.negotiate("hwbreak+")
	// hex("main") = 6d61696e
	if rep := h.cmd("qSymbol:6d61696e"); rep != "E40" {
		t.Fatalf("stripped symbol: %q", rep)
	}
	if !h.log.Contains("reject") {
		t.Fatal("expected rejection log for missing symbol")
	}
	// debug still works on stripped image
	if rep := h.cmd("s"); !strings.HasPrefix(rep, "S") {
		t.Fatalf("step on stripped: %q", rep)
	}
}

func TestIdleTimeoutConverges(t *testing.T) {
	h := newHarness(t, loopProgram(), false, 40*time.Millisecond)
	defer h.close()
	h.negotiate("hwbreak+")
	// No further traffic: the real-clock idle deadline fires deterministically.
	err := <-h.serveErr
	if !errors.Is(err, ErrIdleTimeout) {
		t.Fatalf("idle: %v", err)
	}
	if !h.log.Contains("idle timeout") {
		t.Fatal("missing idle log")
	}
}

func TestDetachThenReconnect(t *testing.T) {
	h := newHarness(t, loopProgram(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")
	if rep := h.cmd("P1=00000005"); rep != "OK" {
		t.Fatalf("write: %q", rep)
	}
	if rep := h.cmd("D"); rep != "OK" {
		t.Fatalf("detach: %q", rep)
	}
	if err := <-h.serveErr; err != nil {
		t.Fatalf("serve: %v", err)
	}
	// server accepts a new session with the same target view
	srvConn2, cliConn2 := protocol.NewPipe()
	link2 := protocol.NewLink(cliConn2, protocol.LinkOptions{
		AckTimeout: 25 * time.Millisecond, MaxRetries: 5})
	serveErr2 := make(chan error, 1)
	go func() { serveErr2 <- h.srv.ServeConn(srvConn2) }()
	old := h.client
	h.client = link2
	h.srvConn = srvConn2
	t.Cleanup(func() { _ = old.Close() })
	if rep := h.negotiate("hwbreak+"); !strings.Contains(rep, "hwbreak+") {
		t.Fatalf("reconnect negotiate: %q", rep)
	}
	// state persisted: r1 still 5
	if rep := h.cmd("p1"); rep != "00000005" {
		t.Fatalf("state after reconnect: %q", rep)
	}
	_ = old
}

func waitFor(h *harness, sub string) {
	for i := 0; i < 100000; i++ {
		if h.log.Contains(sub) {
			return
		}
	}
	h.t.Fatalf("log never contained %q:\n%s", sub, h.log)
}

func TestCapsDegradeOptionalAbsent(t *testing.T) {
	// Non-strict: a client that omits the memory-map feature still connects;
	// qXfer:memory-map degrades to an empty reply instead of an error.
	h := newHarness(t, loopProgram(), false, 0)
	defer h.close()
	rep := h.negotiate("hwbreak+")
	if !strings.Contains(rep, "hwbreak+") {
		t.Fatalf("negotiate: %q", rep)
	}
	if rep := h.cmd("qXfer:memory-map:read"); rep != "" {
		t.Fatalf("memory-map should degrade to empty, got %q", rep)
	}
}

func TestCapsStrictRejectsRequiredMinus(t *testing.T) {
	cb := make([]byte, 4)
	cb[3] = byte(target.OpHALT)
	raw, err := image.NewBuilder().Entry(0x1000).
		Region(image.Region{Name: "flash", Addr: 0x1000, Data: cb, Perm: image.PermRead | image.PermExecute}).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	im, err := image.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := target.New(im)
	if err != nil {
		t.Fatal(err)
	}
	fc := clock.NewRealClock()
	lg := &testLogger{t: t}
	srv := New(tg, Config{
		StrictCaps: true,
		Link:       protocol.LinkOptions{AckTimeout: 25 * time.Millisecond, MaxRetries: 2, Clock: fc},
		Clock:      fc, Logger: lg,
	})
	srvConn, cliConn := protocol.NewPipe()
	client := protocol.NewLink(cliConn, protocol.LinkOptions{AckTimeout: 25 * time.Millisecond, MaxRetries: 2})
	defer client.Close()
	defer srvConn.Close()
	defer lg.close()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServeConn(srvConn) }()

	if err := client.Send([]byte("qSupported:hwbreak-")); err != nil {
		t.Fatal(err)
	}
	body, err := client.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "E02" {
		t.Fatalf("want E02 capability reject, got %q", body)
	}
	if err := <-serveErr; !errors.Is(err, ErrCapabilityRejected) {
		t.Fatalf("serve: %v", err)
	}
	if !lg.Contains("rejected required capability") {
		t.Fatalf("missing reject log: %s", lg)
	}
}

func TestDisconnectConvergesAndReopensClean(t *testing.T) {
	h := newHarness(t, []uint32{
		target.Encode(target.OpMOVI, 1, 0, 7),
		target.Encode(target.OpHALT, 0, 0, 0),
	}, false, 0)
	defer h.close()
	h.negotiate("hwbreak+")
	if rep := h.cmd("P1=00000007"); rep != "OK" {
		t.Fatalf("write: %q", rep)
	}

	// Peer abruptly disconnects mid-session.
	_ = h.client.Close()
	if err := <-h.serveErr; err != nil {
		// clean disconnect returns nil; anything else is fine as long as the
		// server released the session.
		_ = err
	}
	// Wait deterministically (event-driven, no sleep) until the slot frees.
	for i := 0; i < 100000; i++ {
		if !h.srv.Active() {
			break
		}
		if i == 99999 {
			t.Fatal("session never released after disconnect")
		}
	}

	// A brand-new session is accepted on the same target with state intact.
	srvConn2, cliConn2 := protocol.NewPipe()
	link2 := protocol.NewLink(cliConn2, protocol.LinkOptions{AckTimeout: 25 * time.Millisecond, MaxRetries: 5})
	t.Cleanup(func() { _ = link2.Close(); _ = srvConn2.Close() })
	serveErr2 := make(chan error, 1)
	go func() { serveErr2 <- h.srv.ServeConn(srvConn2) }()
	h.client = link2
	if rep := h.negotiate("hwbreak+"); !strings.Contains(rep, "hwbreak+") {
		t.Fatalf("reopen negotiate: %q", rep)
	}
	// r1 still 7: state is a deterministic function of the shared target.
	if rep := h.cmd("p1"); rep != "00000007" {
		t.Fatalf("state after reopen: %q", rep)
	}
}

func TestMalformedCommandRejected(t *testing.T) {
	h := newHarness(t, []uint32{target.Encode(target.OpHALT, 0, 0, 0)}, false, 0)
	defer h.close()
	h.negotiate("hwbreak+")
	// Unknown command -> distinct Exxx, session stays alive for the next call.
	if rep := h.cmd("ZZZ"); rep != "Eff" {
		t.Fatalf("unknown cmd: %q", rep)
	}
	if rep := h.cmd("?"); !strings.HasPrefix(rep, "S") {
		t.Fatalf("session not alive after malformed command: %q", rep)
	}
	if !h.log.Contains("unknown command") {
		t.Fatal("missing rejection log for malformed command")
	}
}
