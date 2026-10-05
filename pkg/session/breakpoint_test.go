package session

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/protocol"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

// countProgram loops r1 = 1..5 at 0x1008, then HALTs. The client must seed
// r3 = 0xffffffff (P3=ffffffff) so r2 counts down to zero.
//
//	0x1000 MOVI r1, 0
//	0x1004 MOVI r2, 5
//	0x1008 ADDI r1, r1, 1   <- breakpoint address
//	0x100c ADD  r2, r2, r3
//	0x1010 JZ   r2, 0x1018
//	0x1014 JMP  0x1008
//	0x1018 HALT
func countProgram() []uint32 {
	return []uint32{
		target.Encode(target.OpMOVI, 1, 0, 0),
		target.Encode(target.OpMOVI, 2, 0, 5),
		target.Encode(target.OpADDI, 1, 0, 1),
		target.Encode(target.OpADD, 2, 3, 0),
		target.Encode(target.OpJZ, 2, 0, 0x1018),
		target.Encode(target.OpJMP, 0, 0, 0x1008),
		target.Encode(target.OpHALT, 0, 0, 0),
	}
}

func condHex(expr string) string { return hex.EncodeToString([]byte(expr)) }

// seedCounter primes r3 = -1 through the wire.
func (h *harness) seedCounter() {
	h.t.Helper()
	if rep := h.cmd("P3=ffffffff"); rep != "OK" {
		h.t.Fatalf("seed r3: %q", rep)
	}
}

func TestConditionalBreakpointOverWire(t *testing.T) {
	h := newHarness(t, countProgram(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")
	h.seedCounter()

	// Conditional breakpoint: stop only when r1 == 3.
	rep := h.cmd("Z1,1008,4;cond=" + condHex("r1 == 3"))
	if rep != "OK" {
		t.Fatalf("set cond bp: %q", rep)
	}
	rep = h.cmd("c")
	if !strings.HasPrefix(rep, "S05;reason:condbp;addr:1008;") {
		t.Fatalf("cond stop reply: %q", rep)
	}
	if rep := h.cmd("p1"); rep != "00000003" {
		t.Fatalf("r1 at cond stop: %q (condition must hold)", rep)
	}
	// Status: 4 arrivals (r1=0..3), 1 stop, 3 skips.
	status := h.cmd("qBp")
	if !strings.HasPrefix(status, "bp:1008,1,4,1,0,"+condHex("r1 == 3")) {
		t.Fatalf("qBp status: %q", status)
	}
	t.Logf("scenario=wire-cond-stop expect=condbp@r1==3,hits4/stops1 actual=%q status=%q", rep, status)
}

func TestConditionalFalseRunsToHalt(t *testing.T) {
	h := newHarness(t, countProgram(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")
	h.seedCounter()

	if rep := h.cmd("Z1,1008,4;cond=" + condHex("r1 == 99")); rep != "OK" {
		t.Fatalf("set: %q", rep)
	}
	if rep := h.cmd("c"); !strings.HasPrefix(rep, "S00;reason:exit") {
		t.Fatalf("condition never true: must run to exit, got %q", rep)
	}
	status := h.cmd("qBp")
	if !strings.HasPrefix(status, "bp:1008,1,5,0,") {
		t.Fatalf("want 5 hits 0 stops, got %q", status)
	}
	t.Logf("scenario=wire-cond-false expect=exit,hits5/stops0 actual=status %q", status)
}

func TestThresholdOverWire(t *testing.T) {
	h := newHarness(t, countProgram(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")
	h.seedCounter()

	if rep := h.cmd("Z1,1008,4;th=3"); rep != "OK" {
		t.Fatalf("set: %q", rep)
	}
	rep := h.cmd("c")
	if !strings.HasPrefix(rep, "S05;reason:condbp;addr:1008;hits:3") {
		t.Fatalf("threshold stop: %q", rep)
	}
	t.Logf("scenario=wire-threshold expect=condbp@hit3 actual=%q", rep)
}

func TestStopReplyReasons(t *testing.T) {
	code := []uint32{
		target.Encode(target.OpMOVI, 1, 0, 1), // 0x1000
		target.Encode(target.OpADDI, 1, 0, 1), // 0x1004
		target.Encode(target.OpHALT, 0, 0, 0), // 0x1008
	}
	h := newHarness(t, code, false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	// step reason
	if rep := h.cmd("s"); rep != "S05;reason:step" {
		t.Fatalf("step reply: %q", rep)
	}
	// dynamic plain breakpoint reason
	if rep := h.cmd("Z1,1004,4"); rep != "OK" {
		t.Fatalf("set: %q", rep)
	}
	if rep := h.cmd("c"); !strings.HasPrefix(rep, "S05;reason:bp;addr:1004;hits:1") {
		t.Fatalf("plain bp reply: %q", rep)
	}
	// exit reason
	if rep := h.cmd("c"); !strings.HasPrefix(rep, "S00;reason:exit") {
		t.Fatalf("exit reply: %q", rep)
	}
	t.Log("scenario=stop-reasons expect=step/bp/exit distinct actual=all-distinct")
}

func TestStopReplyReasonBRK(t *testing.T) {
	// A static BRK instruction in the image reports its own reason. (A BRK
	// re-traps on resume, so it gets a dedicated program.)
	code := []uint32{
		target.Encode(target.OpBRK, 0, 0, 0), // 0x1000
		target.Encode(target.OpHALT, 0, 0, 0),
	}
	h := newHarness(t, code, false, 0)
	defer h.close()
	h.negotiate("hwbreak+")
	if rep := h.cmd("c"); !strings.HasPrefix(rep, "S05;reason:brk;addr:1000") {
		t.Fatalf("brk reply: %q", rep)
	}
	t.Log("scenario=stop-reason-brk expect=reason:brk actual=ok")
}

func TestPauseReasonDistinct(t *testing.T) {
	h := newHarness(t, []uint32{
		target.Encode(target.OpJMP, 0, 0, 0x1000), // infinite loop
	}, false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

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
	if err := h.client.Send([]byte("c")); err != nil {
		t.Fatal(err)
	}
	waitFor(h, "state -> running")
	if err := h.client.SendCtrl(protocol.ByteCtrlC); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-replies:
		if !strings.HasPrefix(r, "S02;reason:pause") {
			t.Fatalf("interrupt reply: %q (must be distinct from breakpoint)", r)
		}
		t.Logf("scenario=pause-reason expect=S02;reason:pause actual=%q", r)
	case <-time.After(2 * time.Second):
		t.Fatalf("no interrupt reply\nLOG:\n%s", h.log)
	}
}

func TestBpEnableDisableOverWire(t *testing.T) {
	h := newHarness(t, countProgram(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")
	h.seedCounter()

	if rep := h.cmd("Z1,1008,4"); rep != "OK" {
		t.Fatalf("set: %q", rep)
	}
	// Enable on a missing address -> E32 (checked while target is halted).
	if rep := h.cmd("qBpEn,1000"); rep != "E32" {
		t.Fatalf("enable missing: %q", rep)
	}
	// Disable: target runs straight to HALT, no hits counted.
	if rep := h.cmd("qBpDis,1008"); rep != "OK" {
		t.Fatalf("disable: %q", rep)
	}
	if rep := h.cmd("c"); !strings.HasPrefix(rep, "S00;reason:exit") {
		t.Fatalf("disabled bp must not stop: %q", rep)
	}
	if status := h.cmd("qBp"); !strings.HasPrefix(status, "bp:1008,0,0,0,") {
		t.Fatalf("disabled bp counted hits: %q", status)
	}
	t.Log("scenario=wire-enable-disable expect=disabled:no-hit,missing:E32 actual=ok")
}

func TestBpConfigureOverWireAtomic(t *testing.T) {
	h := newHarness(t, countProgram(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	if rep := h.cmd("Z1,1008,4;th=2;cond=" + condHex("r1 >= 1")); rep != "OK" {
		t.Fatalf("set: %q", rep)
	}
	before := h.cmd("qBp")
	// Bad condition -> E34, old config fully intact.
	if rep := h.cmd("qBpCfg,1008,cond=" + condHex("r99 ==")); rep != "E34" {
		t.Fatalf("bad cond configure: %q", rep)
	}
	if after := h.cmd("qBp"); after != before {
		t.Fatalf("failed configure mutated slot:\nbefore %q\nafter  %q", before, after)
	}
	// Valid reconfigure of both fields at once.
	if rep := h.cmd("qBpCfg,1008,th=4,cond=" + condHex("r1 >= 2")); rep != "OK" {
		t.Fatalf("configure: %q", rep)
	}
	status := h.cmd("qBp")
	if !strings.HasPrefix(status, "bp:1008,1,0,0,4,"+condHex("r1 >= 2")) {
		t.Fatalf("configure not committed: %q", status)
	}
	// Missing breakpoint -> E32.
	if rep := h.cmd("qBpCfg,1000,th=1"); rep != "E32" {
		t.Fatalf("configure missing: %q", rep)
	}
	t.Log("scenario=wire-configure-atomic expect=bad:E34+intact,valid:committed actual=ok")
}

func TestBpBatchOverWireAtomic(t *testing.T) {
	h := newHarness(t, countProgram(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	if rep := h.cmd("Z1,1000,4"); rep != "OK" {
		t.Fatalf("set: %q", rep)
	}
	before := h.cmd("qBp")
	// One bad spec (bad condition) rejects the whole batch.
	rep := h.cmd("qBpBatch,1004;1008,cond=" + condHex("r1 =="))
	if rep != "E34" {
		t.Fatalf("bad batch: %q", rep)
	}
	if after := h.cmd("qBp"); after != before {
		t.Fatalf("rejected batch left partial state:\nbefore %q\nafter  %q", before, after)
	}
	// Over-capacity batch (1 existing + 4 new > 4 slots) also atomic.
	rep = h.cmd("qBpBatch,1004;1008;100c;1010")
	if rep != "E30" {
		t.Fatalf("over-limit batch: %q", rep)
	}
	if after := h.cmd("qBp"); after != before {
		t.Fatalf("over-limit batch left partial state: %q", after)
	}
	// Valid batch applies everything.
	rep = h.cmd("qBpBatch,1004,th=2;1008,cond=" + condHex("r1 == 1"))
	if rep != "OK" {
		t.Fatalf("valid batch: %q", rep)
	}
	status := h.cmd("qBp")
	if !strings.Contains(status, "1004,1,0,0,2,") ||
		!strings.Contains(status, "1008,1,0,0,0,"+condHex("r1 == 1")) {
		t.Fatalf("batch not applied: %q", status)
	}
	t.Log("scenario=wire-batch-atomic expect=bad-item:reject-all,valid:apply-all actual=ok")
}

func TestBpCapacityOverWire(t *testing.T) {
	h := newHarness(t, countProgram(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	for _, a := range []string{"1000", "1004", "1008", "100c"} {
		if rep := h.cmd("Z1," + a + ",4"); rep != "OK" {
			t.Fatalf("set %s: %q", a, rep)
		}
	}
	before := h.cmd("qBp")
	if rep := h.cmd("Z1,1010,4;th=2"); rep != "E30" {
		t.Fatalf("5th breakpoint: %q", rep)
	}
	if after := h.cmd("qBp"); after != before {
		t.Fatalf("rejected 5th bp changed table: %q", after)
	}
	t.Log("scenario=wire-capacity expect=5th:E30,table-intact actual=ok")
}

func TestBadConditionRejected(t *testing.T) {
	h := newHarness(t, countProgram(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")

	if rep := h.cmd("Z1,1008,4;cond=" + condHex("r1 === 3")); rep != "E34" {
		t.Fatalf("bad cond: %q", rep)
	}
	if status := h.cmd("qBp"); status != "bp:" {
		t.Fatalf("rejected cond bp left a slot: %q", status)
	}
	t.Log("scenario=wire-bad-cond expect=E34,no-slot actual=ok")
}

func TestReconnectConsistentBreakpointView(t *testing.T) {
	h := newHarness(t, countProgram(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")
	h.seedCounter()

	if rep := h.cmd("Z1,1008,4;cond=" + condHex("r1 == 3")); rep != "OK" {
		t.Fatalf("set: %q", rep)
	}
	if rep := h.cmd("c"); !strings.HasPrefix(rep, "S05;reason:condbp") {
		t.Fatalf("run to cond stop: %q", rep)
	}
	viewBefore := h.cmd("qBp")
	if rep := h.cmd("D"); rep != "OK" {
		t.Fatalf("detach: %q", rep)
	}
	if err := <-h.serveErr; err != nil {
		t.Fatalf("serve: %v", err)
	}

	// Reconnect: the breakpoint table, enable flags and hit counts must be
	// exactly the view the previous session left behind.
	srvConn2, cliConn2 := protocol.NewPipe()
	link2 := protocol.NewLink(cliConn2, protocol.LinkOptions{AckTimeout: 25 * time.Millisecond, MaxRetries: 5})
	serveErr2 := make(chan error, 1)
	go func() { serveErr2 <- h.srv.ServeConn(srvConn2) }()
	old := h.client
	h.client = link2
	h.srvConn = srvConn2
	t.Cleanup(func() { _ = old.Close() })
	h.negotiate("hwbreak+")

	viewAfter := h.cmd("qBp")
	if viewAfter != viewBefore {
		t.Fatalf("breakpoint view changed across reconnect:\nbefore %q\nafter  %q", viewBefore, viewAfter)
	}
	if !strings.HasPrefix(viewAfter, "bp:1008,1,4,1,0,") {
		t.Fatalf("unexpected view after reconnect: %q", viewAfter)
	}
	// Execution resumes consistently: next cond stop is hit 8 (r1==3 again
	// never happens; loop ends at r1=5 -> exit). Actually r1 only grows, so
	// the condition never holds again: run to exit.
	if rep := h.cmd("c"); !strings.HasPrefix(rep, "S00;reason:exit") {
		t.Fatalf("resume after reconnect: %q", rep)
	}
	t.Logf("scenario=reconnect-view expect=identical-table actual=%q", viewAfter)
}

func TestBpStatusEmpty(t *testing.T) {
	h := newHarness(t, countProgram(), false, 0)
	defer h.close()
	h.negotiate("hwbreak+")
	if rep := h.cmd("qBp"); rep != "bp:" {
		t.Fatalf("empty status: %q", rep)
	}
	// After clear, the slot disappears from the view (no residue).
	if rep := h.cmd("Z1,1008,4"); rep != "OK" {
		t.Fatalf("set: %q", rep)
	}
	if rep := h.cmd("z1,1008,4"); rep != "OK" {
		t.Fatalf("clear: %q", rep)
	}
	if rep := h.cmd("qBp"); rep != "bp:" {
		t.Fatalf("status after clear: %q", rep)
	}
	t.Log("scenario=status-empty expect=no-residue-after-clear actual=ok")
}

