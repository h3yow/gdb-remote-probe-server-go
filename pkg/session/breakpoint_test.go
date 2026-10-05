package session

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/protocol"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

// incLoop: r1=1, then an incrementing loop with the loop head at 0x1004.
func incLoop() []uint32 {
	return []uint32{
		target.Encode(target.OpMOVI, 1, 0, 1),
		target.Encode(target.OpADDI, 1, 0, 1),
		target.Encode(target.OpJMP, 0, 0, uint16(0x1004)),
	}
}

func condHex(expr string) string { return hex.EncodeToString([]byte(expr)) }

func TestSetBreakpointWithConditionAndThreshold(t *testing.T) {
	h := newHarness(t, incLoop(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	// Bad condition syntax -> E34, no slot consumed.
	if rep := h.cmd("Z1,1004,4;cond=" + condHex("r1 === 3")); rep != "E34" {
		t.Fatalf("bad cond: %q", rep)
	}
	t.Logf("scenario=wire-bad-cond want=E34 got=E34")
	if rep := h.cmd("qBPList"); rep != "none" {
		t.Fatalf("rejected cond consumed a slot: %q", rep)
	}
	// Unknown option -> E33 (bad spec).
	if rep := h.cmd("Z1,1004,4;foo=1"); rep != "E33" {
		t.Fatalf("bad option: %q", rep)
	}
	t.Logf("scenario=wire-bad-option want=E33 got=E33")

	// Valid conditional breakpoint with threshold.
	if rep := h.cmd("Z1,1004,4;th=3;cond=" + condHex("r1 >= 2")); rep != "OK" {
		t.Fatalf("set cond bp: %q", rep)
	}
	// Status view shows condition, threshold, zero counters.
	rep := h.cmd("qBPList")
	want := fmt.Sprintf("1004,1,0,0,3,%s", condHex("r1 >= 2"))
	t.Logf("scenario=wire-status-after-set want=%q got=%q", want, rep)
	if rep != want {
		t.Fatalf("qBPList: got %q want %q", rep, want)
	}
}

func TestConditionalBreakpointOverWire(t *testing.T) {
	h := newHarness(t, incLoop(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	// Stop only when r1 reaches 3. r1 is 1 at the first reach, so hits 1-2
	// are skips and hit 3 stops.
	if rep := h.cmd("Z1,1004,4;cond=" + condHex("r1 == 3")); rep != "OK" {
		t.Fatalf("set: %q", rep)
	}
	if rep := h.cmd("c"); !strings.HasPrefix(rep, "S05") {
		t.Fatalf("continue: %q", rep)
	}
	if rep := h.cmd("p1"); rep != "00000003" {
		t.Fatalf("r1 at cond stop: %q", rep)
	}
	rep := h.cmd("qBPList")
	t.Logf("scenario=wire-cond-stop want=hits=3,skips=2 got=%q", rep)
	if !strings.Contains(rep, "1004,1,3,2,") {
		t.Fatalf("want hits=3 skips=2 in %q", rep)
	}
	// Detailed stop reason: breakpoint, not pause.
	info := h.cmd("qStopInfo")
	t.Logf("scenario=wire-stop-info want=reason=breakpoint got=%q", info)
	if !strings.HasPrefix(info, "reason=breakpoint;addr=1004;hits=3;skips=2") {
		t.Fatalf("qStopInfo: %q", info)
	}
}

func TestThresholdOverWire(t *testing.T) {
	h := newHarness(t, incLoop(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	if rep := h.cmd("Z1,1004,4;th=3"); rep != "OK" {
		t.Fatalf("set: %q", rep)
	}
	if rep := h.cmd("c"); !strings.HasPrefix(rep, "S05") {
		t.Fatalf("continue: %q", rep)
	}
	if rep := h.cmd("p1"); rep != "00000003" {
		t.Fatalf("r1 at threshold stop: %q", rep)
	}
	rep := h.cmd("qBPList")
	t.Logf("scenario=wire-threshold th=3 want=hits=3,skips=2 got=%q", rep)
	if !strings.Contains(rep, "1004,1,3,2,3,") {
		t.Fatalf("want hits=3 skips=2 th=3 in %q", rep)
	}
}

func TestEnableDisableOverWire(t *testing.T) {
	h := newHarness(t, incLoop(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	if rep := h.cmd("Z1,1004,4"); rep != "OK" {
		t.Fatalf("set: %q", rep)
	}
	if rep := h.cmd("qBPDisable,1004"); rep != "OK" {
		t.Fatalf("disable: %q", rep)
	}
	// Enabling a missing breakpoint -> E32.
	if rep := h.cmd("qBPEnable,1008"); rep != "E32" {
		t.Fatalf("enable absent: %q", rep)
	}
	t.Logf("scenario=wire-enable-absent want=E32 got=E32")

	// Continue with the only breakpoint disabled: the loop runs free until
	// the client interrupts; the breakpoint must not count any hits. From
	// here on the replies goroutine is the sole Recv consumer, so every
	// request goes through send/recv (never h.cmd, which would race it).
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
	recv := func(label string) string {
		select {
		case r := <-replies:
			return r
		case <-time.After(2 * time.Second):
			t.Fatalf("no reply for %s\nLOG:\n%s", label, h.log)
			return ""
		}
	}
	send := func(req string) string {
		if err := h.client.Send([]byte(req)); err != nil {
			t.Fatal(err)
		}
		return recv(req)
	}
	if err := h.client.Send([]byte("c")); err != nil {
		t.Fatal(err)
	}
	waitFor(h, "state -> running")
	if err := h.client.SendCtrl(protocol.ByteCtrlC); err != nil {
		t.Fatal(err)
	}
	if rep := recv("ctrlc"); !strings.HasPrefix(rep, "S") {
		t.Fatalf("interrupt: %q", rep)
	}
	rep := send("qBPList")
	t.Logf("scenario=wire-disabled-run want=hits=0 got=%q", rep)
	if !strings.Contains(rep, "1004,0,0,0,1,") {
		t.Fatalf("disabled breakpoint counted hits: %q", rep)
	}
	// Stop info now reports the external interrupt, not a breakpoint.
	if rep := send("qStopInfo"); !strings.HasPrefix(rep, "reason=pause") {
		t.Fatalf("pause stop info: %q", rep)
	}
	t.Logf("scenario=wire-stop-info-pause want=reason=pause got=reason=pause")

	// Re-enable: the next continue stops at the breakpoint.
	if rep := send("qBPEnable,1004"); rep != "OK" {
		t.Fatalf("enable: %q", rep)
	}
	if rep := send("c"); !strings.HasPrefix(rep, "S05") {
		t.Fatalf("continue after enable: %q", rep)
	}
	rep = send("qBPList")
	t.Logf("scenario=wire-reenabled-run want=hits=1 got=%q", rep)
	if !strings.Contains(rep, "1004,1,1,0,1,") {
		t.Fatalf("re-enabled breakpoint: %q", rep)
	}
}

func TestBatchOverWireAtomic(t *testing.T) {
	code := make([]uint32, 6)
	for i := range code {
		code[i] = target.Encode(target.OpMOVI, 1, 0, uint16(i))
	}
	h := newHarness(t, code, false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	// Valid batch of two.
	batch := "1000:1:;1004:2:" + condHex("r1 == 2")
	if rep := h.cmd("qBPBatch," + batch); rep != "OK" {
		t.Fatalf("batch: %q", rep)
	}
	rep := h.cmd("qBPList")
	t.Logf("scenario=wire-batch-commit want=2-entries got=%q", rep)
	if !strings.Contains(rep, "1000,1,0,0,1,") || !strings.Contains(rep, "1004,1,0,0,2,"+condHex("r1 == 2")) {
		t.Fatalf("batch content: %q", rep)
	}

	// Batch with one bad condition: everything rejected, table unchanged.
	before := h.cmd("qBPList")
	rep = h.cmd("qBPBatch,1008:1:;100c:1:" + condHex("broken =="))
	if rep != "E34" {
		t.Fatalf("bad batch: %q", rep)
	}
	after := h.cmd("qBPList")
	t.Logf("scenario=wire-batch-atomic want=unchanged got=before=%q after=%q", before, after)
	if after != before {
		t.Fatalf("rejected batch left partial state: %q -> %q", before, after)
	}

	// Batch that would exceed the slot limit: rejected wholesale (E30).
	rep = h.cmd("qBPBatch,1008:1:;100c:1:;1010:1:")
	if rep != "E30" {
		t.Fatalf("over-capacity batch: %q", rep)
	}
	if got := h.cmd("qBPList"); got != before {
		t.Fatalf("over-capacity batch mutated table: %q", got)
	}
	t.Logf("scenario=wire-batch-capacity want=E30,unchanged got=E30,unchanged")
}

func TestBreakpointViewSurvivesReconnect(t *testing.T) {
	h := newHarness(t, incLoop(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	if rep := h.cmd("Z1,1004,4;th=5;cond=" + condHex("r1 >= 2")); rep != "OK" {
		t.Fatalf("set: %q", rep)
	}
	// Accumulate some hits/skips: th=5 stops at hit 5, so the first stop
	// leaves hits=5 skips=4 recorded.
	if rep := h.cmd("c"); !strings.HasPrefix(rep, "S05") {
		t.Fatalf("continue: %q", rep)
	}
	before := h.cmd("qBPList")
	t.Logf("scenario=reconnect-bp-view before-disconnect=%q", before)

	// Abrupt disconnect, then a fresh session on the same target.
	_ = h.client.Close()
	<-h.serveErr
	for i := 0; i < 100000; i++ {
		if !h.srv.Active() {
			break
		}
	}
	srvConn2, cliConn2 := protocol.NewPipe()
	link2 := protocol.NewLink(cliConn2, protocol.LinkOptions{AckTimeout: 25 * time.Millisecond, MaxRetries: 5})
	t.Cleanup(func() { _ = link2.Close(); _ = srvConn2.Close() })
	serveErr2 := make(chan error, 1)
	go func() { serveErr2 <- h.srv.ServeConn(srvConn2) }()
	h.client = link2
	h.srvConn = srvConn2
	if rep := h.negotiate("hwbreak+"); !strings.Contains(rep, "hwbreak+") {
		t.Fatalf("reconnect negotiate: %q", rep)
	}
	after := h.cmd("qBPList")
	t.Logf("scenario=reconnect-bp-view want=identical got=%q", after)
	if after != before {
		t.Fatalf("breakpoint view changed across reconnect: %q -> %q", before, after)
	}
	// No phantom breakpoints, counters intact: exactly one entry, hits=5.
	if !strings.Contains(after, "1004,1,5,4,5,"+condHex("r1 >= 2")) || strings.Count(after, ";") != 0 {
		t.Fatalf("unexpected breakpoint table after reconnect: %q", after)
	}
	// The breakpoint still works after reconnect: continuing stops again.
	if rep := h.cmd("c"); !strings.HasPrefix(rep, "S05") {
		t.Fatalf("continue after reconnect: %q", rep)
	}
	if rep := h.cmd("qStopInfo"); !strings.HasPrefix(rep, "reason=breakpoint") {
		t.Fatalf("stop info after reconnect: %q", rep)
	}
}
