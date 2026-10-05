package target

import (
	"errors"
	"sync"
	"testing"
)

// countProgram loops r1 = 1..n at the ADDI (loopHead), then HALTs. r3 must be
// seeded with 0xFFFFFFFF (-1) before running so r2 counts down to zero.
//
//	0x1000 MOVI r1, 0
//	0x1004 MOVI r2, n
//	0x1008 ADDI r1, r1, 1   <- loopHead (breakpoint address)
//	0x100c ADD  r2, r2, r3  ; r2--
//	0x1010 JZ   r2, 0x1018
//	0x1014 JMP  0x1008
//	0x1018 HALT
const loopHead = codeAddr + 8

func countProgram(n uint16) []uint32 {
	return []uint32{
		Encode(OpMOVI, 1, 0, 0),
		Encode(OpMOVI, 2, 0, n),
		Encode(OpADDI, 1, 0, 1),
		Encode(OpADD, 2, 3, 0),
		Encode(OpJZ, 2, 0, uint16(codeAddr+24)),
		Encode(OpJMP, 0, 0, uint16(loopHead)),
		Encode(OpHALT, 0, 0, 0),
	}
}

// newCountTarget builds the loop target with r3 = -1 seeded.
func newCountTarget(t *testing.T, n uint16) *Target {
	t.Helper()
	tg := newTarget(t, countProgram(n))
	if err := tg.WriteReg(3, 0xFFFFFFFF); err != nil {
		t.Fatalf("seed r3: %v", err)
	}
	return tg
}

func bpInfo(t *testing.T, tg *Target, addr uint32) BreakpointInfo {
	t.Helper()
	for _, b := range tg.Breakpoints() {
		if b.Addr == addr {
			return b
		}
	}
	t.Fatalf("no breakpoint at %#x", addr)
	return BreakpointInfo{}
}

func TestConditionalBreakpointStopsOnlyWhenTrue(t *testing.T) {
	tg := newCountTarget(t, 5)
	err := tg.SetBreakpointEx(BreakpointSpec{Addr: loopHead, Cond: "r1 == 3"})
	if err != nil {
		t.Fatalf("set cond bp: %v", err)
	}
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	if info.Reason != ReasonBreakpointCond || info.PC != loopHead || info.BPAddr != loopHead {
		t.Fatalf("want cond-breakpoint stop at %#x, got %+v", loopHead, info)
	}
	if v, _ := tg.ReadReg(1); v != 3 {
		t.Fatalf("stopped with r1=%d, want 3 (condition must hold at stop)", v)
	}
	// The bp check runs before the ADDI executes, so r1==3 first holds at the
	// 4th arrival (r1 = 0,1,2,3 at hits 1..4).
	b := bpInfo(t, tg, loopHead)
	if b.Hits != 4 || b.Stops != 1 || b.Skips() != 3 {
		t.Fatalf("hits=%d stops=%d: want 4 hits, 1 stop, 3 skips", b.Hits, b.Stops)
	}
	if info.BPHits != 4 {
		t.Fatalf("halt info BPHits=%d want 4", info.BPHits)
	}
	t.Logf("scenario=cond-true-stop expect=stop@r1==3 actual=reason:%s r1:3 hits:%d stops:%d",
		info.Reason, b.Hits, b.Stops)
}

func TestConditionalBreakpointFalseKeepsRunning(t *testing.T) {
	tg := newCountTarget(t, 5)
	if err := tg.SetBreakpointEx(BreakpointSpec{Addr: loopHead, Cond: "r1 == 99"}); err != nil {
		t.Fatal(err)
	}
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	if info.Reason != ReasonTerminated {
		t.Fatalf("condition never true: target must run to HALT, got %+v", info)
	}
	b := bpInfo(t, tg, loopHead)
	if b.Hits != 5 || b.Stops != 0 {
		t.Fatalf("hits=%d stops=%d: want 5 hits, 0 stops (no false stop)", b.Hits, b.Stops)
	}
	t.Logf("scenario=cond-false-nostop expect=run-to-halt actual=reason:%s hits:%d stops:%d",
		info.Reason, b.Hits, b.Stops)
}

func TestMemoryConditionBreakpoint(t *testing.T) {
	tg := newCountTarget(t, 5)
	// Seed ram[0x2000] = 42; condition reads memory.
	if err := tg.WriteMem(ramAddr, []byte{42, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if err := tg.SetBreakpointEx(BreakpointSpec{Addr: loopHead, Cond: "u32[0x2000] == 42 && r1 >= 2"}); err != nil {
		t.Fatal(err)
	}
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	if info.Reason != ReasonBreakpointCond {
		t.Fatalf("want cond stop, got %+v", info)
	}
	if v, _ := tg.ReadReg(1); v != 2 {
		t.Fatalf("stopped at r1=%d, want 2 (first hit where r1>=2)", v)
	}
	t.Logf("scenario=mem-cond expect=stop@r1==2 actual=reason:%s r1:2", info.Reason)

	// Reconfigure to a condition on a different memory value: never true.
	if err := tg.ConfigureBreakpoint(loopHead, "u32[0x2000] == 7", 0); err != nil {
		t.Fatal(err)
	}
	info, err = tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	if info.Reason != ReasonTerminated {
		t.Fatalf("mem condition false: want run to HALT, got %+v", info)
	}
	t.Logf("scenario=mem-cond-false expect=run-to-halt actual=reason:%s", info.Reason)
}

func TestHitThreshold(t *testing.T) {
	tg := newCountTarget(t, 5)
	if err := tg.SetBreakpointEx(BreakpointSpec{Addr: loopHead, Threshold: 3}); err != nil {
		t.Fatal(err)
	}
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	if info.Reason != ReasonBreakpointCond {
		t.Fatalf("threshold stop: got %+v", info)
	}
	if v, _ := tg.ReadReg(1); v != 2 {
		t.Fatalf("stopped at hit r1=%d, want 2 (3rd arrival, r1 not yet incremented)", v)
	}
	// Past the threshold every further hit stops: next stop is hit 4.
	info, err = tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	if info.Reason != ReasonBreakpointCond || info.BPHits != 4 {
		t.Fatalf("post-threshold stop: %+v", info)
	}
	b := bpInfo(t, tg, loopHead)
	if b.Hits != 4 || b.Stops != 2 || b.Skips() != 2 {
		t.Fatalf("hits=%d stops=%d: want 4 hits, 2 stops, 2 skips", b.Hits, b.Stops)
	}
	t.Logf("scenario=threshold-3 expect=stop@hit3,hit4 actual=hits:%d stops:%d", b.Hits, b.Stops)
}

func TestPlainBreakpointReasonUnchanged(t *testing.T) {
	tg := newCountTarget(t, 5)
	if err := tg.SetBreakpoint(loopHead); err != nil {
		t.Fatal(err)
	}
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	if info.Reason != ReasonBreakpoint {
		t.Fatalf("plain bp must keep ReasonBreakpoint, got %s", info.Reason)
	}
	b := bpInfo(t, tg, loopHead)
	if b.Hits != 1 || b.Stops != 1 {
		t.Fatalf("hits=%d stops=%d want 1/1", b.Hits, b.Stops)
	}
	t.Logf("scenario=plain-bp expect=ReasonBreakpoint actual=%s", info.Reason)
}

func TestDisabledBreakpointNeverHits(t *testing.T) {
	tg := newCountTarget(t, 3)
	if err := tg.SetBreakpoint(loopHead); err != nil {
		t.Fatal(err)
	}
	if err := tg.EnableBreakpoint(loopHead, false); err != nil {
		t.Fatal(err)
	}
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	if info.Reason != ReasonTerminated {
		t.Fatalf("disabled bp must not stop, got %+v", info)
	}
	b := bpInfo(t, tg, loopHead)
	if b.Hits != 0 || b.Enabled {
		t.Fatalf("disabled bp counted hits=%d enabled=%v", b.Hits, b.Enabled)
	}
	t.Logf("scenario=disabled-bp expect=no-hit run-to-halt actual=reason:%s hits:%d", info.Reason, b.Hits)

	// Re-enable flow on a fresh run: Reset clears the table; reinstall.
	if err := tg.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := tg.SetBreakpoint(loopHead); err != nil {
		t.Fatal(err)
	}
	if err := tg.EnableBreakpoint(loopHead, true); err != nil {
		t.Fatal(err)
	}
	if err := tg.WriteReg(3, 0xFFFFFFFF); err != nil {
		t.Fatal(err)
	}
	info, err = tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	if info.Reason != ReasonBreakpoint {
		t.Fatalf("re-enabled bp must stop, got %+v", info)
	}
}

func TestEnableDisableMissingAndRepeat(t *testing.T) {
	tg := newCountTarget(t, 1)
	if err := tg.EnableBreakpoint(loopHead, true); !errors.Is(err, ErrNoBreakpoint) {
		t.Fatalf("enable missing: want ErrNoBreakpoint, got %v", err)
	}
	if err := tg.SetBreakpoint(loopHead); err != nil {
		t.Fatal(err)
	}
	// Repeated enable/disable is stable.
	for i := 0; i < 3; i++ {
		if err := tg.EnableBreakpoint(loopHead, false); err != nil {
			t.Fatalf("disable #%d: %v", i, err)
		}
		if bpInfo(t, tg, loopHead).Enabled {
			t.Fatalf("disable #%d not effective", i)
		}
		if err := tg.EnableBreakpoint(loopHead, true); err != nil {
			t.Fatalf("enable #%d: %v", i, err)
		}
		if !bpInfo(t, tg, loopHead).Enabled {
			t.Fatalf("enable #%d not effective", i)
		}
	}
	t.Log("scenario=enable-disable-repeat expect=stable actual=stable x3")
}

func TestConfigureBreakpointAtomicFailure(t *testing.T) {
	tg := newCountTarget(t, 2)
	if err := tg.SetBreakpointEx(BreakpointSpec{Addr: loopHead, Cond: "r1 == 1", Threshold: 2}); err != nil {
		t.Fatal(err)
	}
	before := bpInfo(t, tg, loopHead)
	// Bad condition: rejected, old cond+threshold fully intact.
	if err := tg.ConfigureBreakpoint(loopHead, "r99 == 1", 5); !errors.Is(err, ErrBPBadCond) {
		t.Fatalf("want ErrBPBadCond, got %v", err)
	}
	after := bpInfo(t, tg, loopHead)
	if after != before {
		t.Fatalf("failed configure mutated slot: before=%+v after=%+v", before, after)
	}
	// Missing breakpoint.
	if err := tg.ConfigureBreakpoint(codeAddr, "r1 == 1", 0); !errors.Is(err, ErrNoBreakpoint) {
		t.Fatalf("want ErrNoBreakpoint, got %v", err)
	}
	// Valid configure commits both fields at once.
	if err := tg.ConfigureBreakpoint(loopHead, "r1 == 2", 1); err != nil {
		t.Fatal(err)
	}
	got := bpInfo(t, tg, loopHead)
	if got.Cond != "r1 == 2" || got.Threshold != 1 {
		t.Fatalf("configure not committed atomically: %+v", got)
	}
	t.Log("scenario=configure-atomic expect=bad-cond-keeps-old,valid-commits-both actual=ok")
}

func TestBatchApplyAtomic(t *testing.T) {
	tg := newCountTarget(t, 1)
	if err := tg.SetBreakpoint(codeAddr); err != nil {
		t.Fatal(err)
	}
	before := tg.Breakpoints()

	// Batch with one bad condition: nothing applied.
	err := tg.ApplyBreakpoints([]BreakpointSpec{
		{Addr: codeAddr + 4},
		{Addr: loopHead, Cond: "r1 =="},
	})
	if !errors.Is(err, ErrBPBadCond) {
		t.Fatalf("want ErrBPBadCond, got %v", err)
	}
	if got := tg.Breakpoints(); len(got) != len(before) || got[0] != before[0] {
		t.Fatalf("rejected batch left partial state: %+v", got)
	}

	// Batch exceeding capacity: nothing applied.
	err = tg.ApplyBreakpoints([]BreakpointSpec{
		{Addr: codeAddr + 4},
		{Addr: loopHead},
		{Addr: codeAddr + 12},
		{Addr: codeAddr + 16}, // 1 existing + 4 new = 5 > 4 slots
	})
	if !errors.Is(err, ErrBPLimit) {
		t.Fatalf("want ErrBPLimit, got %v", err)
	}
	if got := tg.Breakpoints(); len(got) != 1 {
		t.Fatalf("over-limit batch left partial state: %+v", got)
	}

	// Valid batch: all applied, including reconfigure of the existing slot.
	err = tg.ApplyBreakpoints([]BreakpointSpec{
		{Addr: codeAddr, Threshold: 2}, // reconfigure existing
		{Addr: codeAddr + 4, Cond: "r1 == 1"},
		{Addr: loopHead},
	})
	if err != nil {
		t.Fatalf("valid batch: %v", err)
	}
	got := tg.Breakpoints()
	if len(got) != 3 {
		t.Fatalf("batch applied: %+v", got)
	}
	if got[0].Threshold != 2 || got[1].Cond != "r1 == 1" {
		t.Fatalf("batch specs not applied: %+v", got)
	}
	t.Log("scenario=batch-atomic expect=bad-item-rejects-all,valid-applies-all actual=ok")
}

func TestSetBreakpointExIdempotent(t *testing.T) {
	tg := newCountTarget(t, 3)
	spec := BreakpointSpec{Addr: loopHead, Cond: "r1 >= 1", Threshold: 2}
	for i := 0; i < 3; i++ {
		if err := tg.SetBreakpointEx(spec); err != nil {
			t.Fatalf("set #%d: %v", i, err)
		}
	}
	if got := tg.Breakpoints(); len(got) != 1 {
		t.Fatalf("repeated set duplicated slot: %+v", got)
	}
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	if info.Reason != ReasonBreakpointCond || info.BPHits != 2 {
		t.Fatalf("stop: %+v", info)
	}
	// Re-set after hits: counters preserved.
	if err := tg.SetBreakpointEx(spec); err != nil {
		t.Fatal(err)
	}
	if b := bpInfo(t, tg, loopHead); b.Hits != 2 {
		t.Fatalf("re-set lost hit count: %d", b.Hits)
	}
	t.Log("scenario=repeated-set expect=single-slot counters-preserved actual=ok")
}

func TestConcurrentBreakpointOpsRaceStable(t *testing.T) {
	// Infinite loop target; hammer management ops from several goroutines
	// while execution starts/stops. Correctness bar: no data race, no panic,
	// and after Interrupt the table is internally consistent.
	code := []uint32{Encode(OpJMP, 0, 0, uint16(codeAddr))}
	tg := newTarget(t, code)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	ops := []func(){
		func() { _ = tg.SetBreakpoint(codeAddr) },
		func() { _ = tg.ClearBreakpoint(codeAddr) },
		func() { _ = tg.EnableBreakpoint(codeAddr, true) },
		func() { _ = tg.ConfigureBreakpoint(codeAddr, "r1 == 1", 1) },
		func() { _ = tg.ApplyBreakpoints([]BreakpointSpec{{Addr: codeAddr}}) },
		func() { _ = tg.Breakpoints() },
	}
	for i, op := range ops {
		wg.Add(1)
		go func(i int, op func()) {
			defer wg.Done()
			for n := 0; n < 200; n++ {
				op()
			}
		}(i, op)
	}
	wg.Wait()
	close(stop)

	// Serial ground truth after the storm: every op behaves deterministically.
	if err := tg.SetBreakpoint(codeAddr); err != nil {
		t.Fatalf("set after storm: %v", err)
	}
	if err := tg.EnableBreakpoint(codeAddr, false); err != nil {
		t.Fatalf("disable after storm: %v", err)
	}
	b := bpInfo(t, tg, codeAddr)
	if b.Enabled {
		t.Fatal("disable not effective after concurrent storm")
	}
	t.Log("scenario=concurrent-ops expect=no-race consistent-final-state actual=ok")
}
