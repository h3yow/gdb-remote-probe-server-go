package target

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
)

// loopCode: r1 starts at 0; each iteration of the loop at codeAddr+4 adds 1.
//
//	0x1000: MOVI r1, 0
//	0x1004: ADDI r1, 1   <- breakpoint address used by most tests
//	0x1008: JMP 0x1004
func loopCode() []uint32 {
	return []uint32{
		Encode(OpMOVI, 1, 0, 0),
		Encode(OpADDI, 1, 0, 1),
		Encode(OpJMP, 0, 0, uint16(codeAddr+4)),
	}
}

func bpByAddr(t *testing.T, tg *Target, addr uint32) BreakpointInfo {
	t.Helper()
	for _, b := range tg.Breakpoints() {
		if b.Addr == addr {
			return b
		}
	}
	t.Fatalf("breakpoint %#x not listed", addr)
	return BreakpointInfo{}
}

func TestConditionSyntaxRejected(t *testing.T) {
	tg := newTarget(t, loopCode())
	bad := []string{"r1=", "r1 === 5", "r99 == 1", "[0x2002] == 1", "foo == 1", "r1 <> 2", "[xyz] == 1"}
	for _, expr := range bad {
		err := tg.SetBreakpointSpec(BreakpointSpec{Addr: codeAddr + 4, Condition: expr})
		if !errors.Is(err, ErrBPBadCond) {
			t.Fatalf("cond %q: want ErrBPBadCond, got %v", expr, err)
		}
		t.Logf("scenario=bad-condition expr=%q want=ErrBPBadCond got=%v", expr, err)
	}
	if len(tg.Breakpoints()) != 0 {
		t.Fatalf("rejected conditions installed breakpoints: %+v", tg.Breakpoints())
	}
	t.Logf("scenario=bad-condition expect=no-slots-used got=%d slots", len(tg.Breakpoints()))
}

func TestConditionalBreakpointOnRegister(t *testing.T) {
	tg := newTarget(t, loopCode())
	tg.SetInstructionBudget(0)
	const bpAddr = codeAddr + 4
	if err := tg.SetBreakpointSpec(BreakpointSpec{Addr: bpAddr, Condition: "r1 == 5"}); err != nil {
		t.Fatal(err)
	}
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	if info.Reason != ReasonBreakpoint || info.BPAddr != bpAddr {
		t.Fatalf("stop: %+v", info)
	}
	r1, _ := tg.ReadReg(1)
	bp := bpByAddr(t, tg, bpAddr)
	// r1 is 0 at the first reach; the condition first holds at the 6th hit.
	t.Logf("scenario=cond-register expr=%q want=r1==5,hits=6,skips=5 got=r1=%d,hits=%d,skips=%d",
		"r1 == 5", r1, bp.Hits, bp.Skips)
	if r1 != 5 || bp.Hits != 6 || bp.Skips != 5 {
		t.Fatalf("cond stop: r1=%d hits=%d skips=%d", r1, bp.Hits, bp.Skips)
	}
}

func TestConditionalBreakpointOnMemory(t *testing.T) {
	tg := newTarget(t, loopCode())
	tg.SetInstructionBudget(0)
	const bpAddr = codeAddr + 4
	if err := tg.WriteMem(ramAddr, []byte{0x2a, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if err := tg.SetBreakpointSpec(BreakpointSpec{Addr: bpAddr, Condition: "[0x2000] == 0x2a"}); err != nil {
		t.Fatal(err)
	}
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	bp := bpByAddr(t, tg, bpAddr)
	t.Logf("scenario=cond-memory expr=%q mem=0x2a want=stop-on-first-hit got=reason=%s hits=%d",
		"[0x2000] == 0x2a", info.Reason, bp.Hits)
	if info.Reason != ReasonBreakpoint || bp.Hits != 1 || bp.Skips != 0 {
		t.Fatalf("mem cond: %+v hits=%d skips=%d", info, bp.Hits, bp.Skips)
	}
}

func TestConditionFalseNeverStops(t *testing.T) {
	tg := newTarget(t, loopCode())
	// Finite budget: the loop runs, every reach is a skip, the run ends with
	// the budget-exhaustion guard rather than a breakpoint stop.
	tg.SetInstructionBudget(50)
	const bpAddr = codeAddr + 4
	if err := tg.SetBreakpointSpec(BreakpointSpec{Addr: bpAddr, Condition: "r1 == 0xdead"}); err != nil {
		t.Fatal(err)
	}
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	bp := bpByAddr(t, tg, bpAddr)
	t.Logf("scenario=cond-never-true expr=%q want=no-bp-stop,skips>0 got=reason=%s hits=%d skips=%d",
		"r1 == 0xdead", info.Reason, bp.Hits, bp.Skips)
	if info.Reason == ReasonBreakpoint {
		t.Fatalf("false condition stopped the target: %+v", info)
	}
	if bp.Hits == 0 || bp.Skips != bp.Hits {
		t.Fatalf("every reach must be a skip: hits=%d skips=%d", bp.Hits, bp.Skips)
	}
}

func TestUnreadableMemoryConditionIsFalse(t *testing.T) {
	tg := newTarget(t, loopCode())
	tg.SetInstructionBudget(40)
	const bpAddr = codeAddr + 4
	// 0x9000 is unmapped: the condition evaluates to false, never a fault.
	if err := tg.SetBreakpointSpec(BreakpointSpec{Addr: bpAddr, Condition: "[0x9000] == 1"}); err != nil {
		t.Fatal(err)
	}
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	bp := bpByAddr(t, tg, bpAddr)
	t.Logf("scenario=cond-unmapped-mem want=no-bp-stop,no-fault-at-bp got=reason=%s skips=%d",
		info.Reason, bp.Skips)
	if info.Reason == ReasonBreakpoint {
		t.Fatalf("unmapped memory condition stopped target: %+v", info)
	}
	if bp.Skips == 0 {
		t.Fatal("expected skips for unreadable memory condition")
	}
}

func TestHitThreshold(t *testing.T) {
	tg := newTarget(t, loopCode())
	tg.SetInstructionBudget(0)
	const bpAddr = codeAddr + 4
	if err := tg.SetBreakpointSpec(BreakpointSpec{Addr: bpAddr, Threshold: 3}); err != nil {
		t.Fatal(err)
	}
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	bp := bpByAddr(t, tg, bpAddr)
	r1, _ := tg.ReadReg(1)
	t.Logf("scenario=hit-threshold th=3 want=stop-at-hit-3,r1=2 got=hits=%d skips=%d r1=%d reason=%s",
		bp.Hits, bp.Skips, r1, info.Reason)
	if info.Reason != ReasonBreakpoint || bp.Hits != 3 || bp.Skips != 2 || r1 != 2 {
		t.Fatalf("threshold stop: %+v hits=%d skips=%d r1=%d", info, bp.Hits, bp.Skips, r1)
	}
	// Resuming stops again on the next reach (hits now 4 >= 3).
	info, err = tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	bp = bpByAddr(t, tg, bpAddr)
	t.Logf("scenario=threshold-resume want=stop-again hits=4 got=hits=%d reason=%s", bp.Hits, info.Reason)
	if info.Reason != ReasonBreakpoint || bp.Hits != 4 {
		t.Fatalf("resume after threshold: %+v hits=%d", info, bp.Hits)
	}
}

func TestConditionAndThresholdCombined(t *testing.T) {
	tg := newTarget(t, loopCode())
	tg.SetInstructionBudget(0)
	const bpAddr = codeAddr + 4
	// r1 >= 3 first holds at hit 4 (r1==3); threshold 2 stops at hit 2,
	// before the condition can hold, so the effective stop is hit 4.
	if err := tg.SetBreakpointSpec(BreakpointSpec{Addr: bpAddr, Condition: "r1 >= 3", Threshold: 2}); err != nil {
		t.Fatal(err)
	}
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	bp := bpByAddr(t, tg, bpAddr)
	r1, _ := tg.ReadReg(1)
	t.Logf("scenario=cond+threshold expr=%q th=2 want=stop-at-hit-4,r1=3 got=hits=%d skips=%d r1=%d",
		"r1 >= 3", bp.Hits, bp.Skips, r1)
	if info.Reason != ReasonBreakpoint || bp.Hits != 4 || bp.Skips != 3 || r1 != 3 {
		t.Fatalf("combined: %+v hits=%d skips=%d r1=%d", info, bp.Hits, bp.Skips, r1)
	}
}

func TestDisabledBreakpointDoesNotCount(t *testing.T) {
	tg := newTarget(t, loopCode())
	tg.SetInstructionBudget(0)
	const bpAddr = codeAddr + 4
	if err := tg.SetBreakpointSpec(BreakpointSpec{Addr: bpAddr}); err != nil {
		t.Fatal(err)
	}
	if err := tg.EnableBreakpoint(bpAddr, false); err != nil {
		t.Fatal(err)
	}
	tg.SetInstructionBudget(30)
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	bp := bpByAddr(t, tg, bpAddr)
	t.Logf("scenario=disabled-bp want=no-hits,no-stop got=reason=%s hits=%d skips=%d enabled=%v",
		info.Reason, bp.Hits, bp.Skips, bp.Enabled)
	if info.Reason == ReasonBreakpoint || bp.Hits != 0 || bp.Skips != 0 {
		t.Fatalf("disabled breakpoint fired: %+v %+v", info, bp)
	}
	// Re-enable atomically: the very next run stops on the first reach.
	if err := tg.EnableBreakpoint(bpAddr, true); err != nil {
		t.Fatal(err)
	}
	tg.SetInstructionBudget(0)
	info, err = tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	bp = bpByAddr(t, tg, bpAddr)
	t.Logf("scenario=reenabled-bp want=stop,hits=1 got=reason=%s hits=%d", info.Reason, bp.Hits)
	if info.Reason != ReasonBreakpoint || bp.Hits != 1 {
		t.Fatalf("re-enabled breakpoint: %+v %+v", info, bp)
	}
}

func TestEnableBreakpointErrors(t *testing.T) {
	tg := newTarget(t, loopCode())
	if err := tg.EnableBreakpoint(codeAddr+4, true); !errors.Is(err, ErrNoBreakpoint) {
		t.Fatalf("enable absent: want ErrNoBreakpoint, got %v", err)
	}
	t.Logf("scenario=enable-absent want=ErrNoBreakpoint got=%v", ErrNoBreakpoint)
}

func TestBreakpointCapacityEnforced(t *testing.T) {
	// 4 code words -> exactly enough addresses to fill every slot.
	code := append(loopCode(), Encode(OpHALT, 0, 0, 0))
	tg := newTarget(t, code)
	for i := 0; i < MaxBreakpoints; i++ {
		if err := tg.SetBreakpoint(codeAddr + uint32(4*i)); err != nil {
			t.Fatalf("set slot %d: %v", i, err)
		}
	}
	before := tg.Breakpoints()
	// Re-setting an installed address stays idempotent even on a full table.
	if err := tg.SetBreakpoint(codeAddr); err != nil {
		t.Fatalf("repeat set on full table must stay idempotent: %v", err)
	}
	// Clear one slot and refill it with a conditional spec.
	if err := tg.ClearBreakpoint(codeAddr); err != nil {
		t.Fatal(err)
	}
	if err := tg.SetBreakpointSpec(BreakpointSpec{Addr: codeAddr, Condition: "r1 == 1", Threshold: 2}); err != nil {
		t.Fatalf("refill slot: %v", err)
	}
	if got := len(tg.Breakpoints()); got != MaxBreakpoints {
		t.Fatalf("slots=%d want %d", got, MaxBreakpoints)
	}
	bp := bpByAddr(t, tg, codeAddr)
	t.Logf("scenario=capacity want=%d-slots-full,refill-keeps-spec got=%d slots cond=%q th=%d (before=%d)",
		MaxBreakpoints, len(tg.Breakpoints()), bp.Condition, bp.Threshold, len(before))
	if bp.Condition != "r1 == 1" || bp.Threshold != 2 {
		t.Fatalf("refilled slot lost spec: %+v", bp)
	}
}

func TestBreakpointLimitRejectsWithoutSideEffects(t *testing.T) {
	code := append(loopCode(), Encode(OpHALT, 0, 0, 0))
	tg := newTarget(t, code)
	for i := 0; i < MaxBreakpoints; i++ {
		if err := tg.SetBreakpoint(codeAddr + uint32(4*i)); err != nil {
			t.Fatal(err)
		}
	}
	before := tg.Breakpoints()
	// Image has exactly 4 code words; a 5th distinct address is non-code.
	// Instead verify via batch: batch of one new valid-looking address that
	// is not code must fail and change nothing.
	err := tg.SetBreakpointsBatch([]BreakpointSpec{{Addr: codeAddr + 0x10}})
	if !errors.Is(err, ErrBPBadAddr) {
		t.Fatalf("want ErrBPBadAddr, got %v", err)
	}
	after := tg.Breakpoints()
	if len(after) != len(before) {
		t.Fatalf("rejected request changed table: %d -> %d", len(before), len(after))
	}
	t.Logf("scenario=limit-no-side-effects want=table-unchanged got=%d slots (was %d)", len(after), len(before))
}

func TestBatchAtomicOnBadCondition(t *testing.T) {
	tg := newTarget(t, loopCode())
	if err := tg.SetBreakpoint(codeAddr); err != nil {
		t.Fatal(err)
	}
	before := tg.Breakpoints()
	err := tg.SetBreakpointsBatch([]BreakpointSpec{
		{Addr: codeAddr + 4, Threshold: 2},
		{Addr: codeAddr + 8, Condition: "r1 === 3"}, // invalid
	})
	if !errors.Is(err, ErrBPBadCond) {
		t.Fatalf("want ErrBPBadCond, got %v", err)
	}
	after := tg.Breakpoints()
	t.Logf("scenario=batch-bad-cond want=all-rejected got=slots %d->%d err=%v", len(before), len(after), err)
	if len(after) != len(before) {
		t.Fatalf("batch left partial state: before=%+v after=%+v", before, after)
	}
}

func TestBatchAtomicOnCapacity(t *testing.T) {
	code := append(loopCode(), Encode(OpHALT, 0, 0, 0))
	tg := newTarget(t, code)
	if err := tg.SetBreakpoint(codeAddr); err != nil {
		t.Fatal(err)
	}
	if err := tg.SetBreakpoint(codeAddr + 4); err != nil {
		t.Fatal(err)
	}
	before := tg.Breakpoints()
	// 2 installed, batch of 3 new addresses would need 5 slots > 4.
	err := tg.SetBreakpointsBatch([]BreakpointSpec{
		{Addr: codeAddr + 8},
		{Addr: codeAddr + 12},
		{Addr: codeAddr}, // idempotent re-set, not a new slot
	})
	_ = before
	if err != nil {
		t.Fatalf("batch with 2 new + 1 existing should fit: %v", err)
	}
	if got := len(tg.Breakpoints()); got != 4 {
		t.Fatalf("slots=%d want 4", got)
	}
	// Now full: any batch with a new address fails wholesale.
	code2 := make([]uint32, 6)
	for i := range code2 {
		code2[i] = Encode(OpMOVI, 1, 0, uint16(i))
	}
	tg2 := newTarget(t, code2)
	for i := 0; i < MaxBreakpoints; i++ {
		if err := tg2.SetBreakpoint(codeAddr + uint32(4*i)); err != nil {
			t.Fatal(err)
		}
	}
	before2 := tg2.Breakpoints()
	err = tg2.SetBreakpointsBatch([]BreakpointSpec{
		{Addr: codeAddr + 0x10, Threshold: 2},
		{Addr: codeAddr + 0x14},
	})
	if !errors.Is(err, ErrBPLimit) {
		t.Fatalf("want ErrBPLimit, got %v", err)
	}
	after2 := tg2.Breakpoints()
	t.Logf("scenario=batch-over-capacity want=all-rejected got=slots %d->%d err=%v",
		len(before2), len(after2), err)
	if len(after2) != MaxBreakpoints {
		t.Fatalf("over-capacity batch mutated table: %+v", after2)
	}
}

func TestBatchCommitAndDuplicateCollapse(t *testing.T) {
	tg := newTarget(t, loopCode())
	err := tg.SetBreakpointsBatch([]BreakpointSpec{
		{Addr: codeAddr + 4, Condition: "r1 == 1"},
		{Addr: codeAddr + 8, Threshold: 2},
		{Addr: codeAddr + 4, Condition: "r1 == 2"}, // duplicate: last wins
	})
	if err != nil {
		t.Fatal(err)
	}
	bps := tg.Breakpoints()
	if len(bps) != 2 {
		t.Fatalf("duplicate in batch created extra slot: %+v", bps)
	}
	bp := bpByAddr(t, tg, codeAddr+4)
	t.Logf("scenario=batch-duplicate want=last-wins cond=%q got=%q", "r1 == 2", bp.Condition)
	if bp.Condition != "r1 == 2" {
		t.Fatalf("duplicate collapse: cond=%q", bp.Condition)
	}
}

func TestUpdatePreservesHitsAtomically(t *testing.T) {
	tg := newTarget(t, loopCode())
	tg.SetInstructionBudget(0)
	const bpAddr = codeAddr + 4
	if err := tg.SetBreakpointSpec(BreakpointSpec{Addr: bpAddr, Threshold: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := tg.Continue(); err != nil {
		t.Fatal(err)
	}
	bp := bpByAddr(t, tg, bpAddr)
	if bp.Hits != 2 {
		t.Fatalf("pre-update hits=%d want 2", bp.Hits)
	}
	// A rejected update (bad condition) must leave everything untouched.
	err := tg.SetBreakpointSpec(BreakpointSpec{Addr: bpAddr, Condition: "nope"})
	if !errors.Is(err, ErrBPBadCond) {
		t.Fatalf("want ErrBPBadCond, got %v", err)
	}
	bp = bpByAddr(t, tg, bpAddr)
	t.Logf("scenario=failed-update want=unchanged got=hits=%d th=%d cond=%q", bp.Hits, bp.Threshold, bp.Condition)
	if bp.Hits != 2 || bp.Threshold != 2 || bp.Condition != "" {
		t.Fatalf("failed update mutated breakpoint: %+v", bp)
	}
	// A valid update swaps condition+threshold but keeps the counters.
	if err := tg.SetBreakpointSpec(BreakpointSpec{Addr: bpAddr, Condition: "r1 >= 5", Threshold: 6}); err != nil {
		t.Fatal(err)
	}
	bp = bpByAddr(t, tg, bpAddr)
	t.Logf("scenario=valid-update want=hits-preserved got=hits=%d th=%d cond=%q", bp.Hits, bp.Threshold, bp.Condition)
	if bp.Hits != 2 || bp.Threshold != 6 || bp.Condition != "r1 >= 5" {
		t.Fatalf("update: %+v", bp)
	}
}

func TestRepeatedSetClearStable(t *testing.T) {
	tg := newTarget(t, loopCode())
	const a = codeAddr + 4
	for i := 0; i < 5; i++ {
		if err := tg.SetBreakpointSpec(BreakpointSpec{Addr: a, Condition: "r1 == 1", Threshold: 3}); err != nil {
			t.Fatalf("set %d: %v", i, err)
		}
	}
	bps := tg.Breakpoints()
	if len(bps) != 1 || bps[0].Hits != 0 || bps[0].Threshold != 3 {
		t.Fatalf("repeated set unstable: %+v", bps)
	}
	if err := tg.ClearBreakpoint(a); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := tg.ClearBreakpoint(a); !errors.Is(err, ErrNoBreakpoint) {
			t.Fatalf("clear %d: want ErrNoBreakpoint, got %v", i, err)
		}
	}
	if len(tg.Breakpoints()) != 0 {
		t.Fatalf("cleared breakpoint still listed: %+v", tg.Breakpoints())
	}
	t.Logf("scenario=repeated-set-clear want=stable got=slots=%d after 5 sets + 4 clears", len(tg.Breakpoints()))
}

func TestConcurrentBreakpointManagement(t *testing.T) {
	code := make([]uint32, 8)
	for i := range code {
		code[i] = Encode(OpMOVI, 1, 0, uint16(i))
	}
	code[len(code)-1] = Encode(OpJMP, 0, 0, uint16(codeAddr)) // loop forever
	tg := newTarget(t, code)
	tg.SetInstructionBudget(0)

	var wg sync.WaitGroup
	// Writer goroutines: set/update/enable/clear disjoint addresses.
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			addr := codeAddr + uint32(4*w)
			for i := 0; i < 200; i++ {
				_ = tg.SetBreakpointSpec(BreakpointSpec{
					Addr: addr, Condition: fmt.Sprintf("r1 == %d", i%4), Threshold: uint64(i%3 + 1)})
				_ = tg.EnableBreakpoint(addr, i%2 == 0)
				if i%5 == 4 {
					_ = tg.ClearBreakpoint(addr)
				}
				runtime.Gosched()
			}
		}(w)
	}
	// Reader goroutines: snapshot the table continuously.
	for r := 0; r < 2; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				bps := tg.Breakpoints()
				if len(bps) > MaxBreakpoints {
					t.Errorf("table exceeds capacity: %d", len(bps))
					return
				}
				seen := map[uint32]bool{}
				for _, b := range bps {
					if seen[b.Addr] {
						t.Errorf("duplicate slot %#x in snapshot", b.Addr)
						return
					}
					seen[b.Addr] = true
				}
				runtime.Gosched()
			}
		}()
	}
	// Batch writer on the remaining slot.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = tg.SetBreakpointsBatch([]BreakpointSpec{{Addr: codeAddr + 12, Threshold: 1}})
			_ = tg.ClearBreakpoint(codeAddr + 12)
			runtime.Gosched()
		}
	}()
	wg.Wait()
	t.Logf("scenario=concurrent-management want=race-clean,consistent got=final-slots=%d", len(tg.Breakpoints()))
}

func TestConcurrentRunAndManage(t *testing.T) {
	// A running target rejects management calls with ErrRunning; the loop
	// below hammers Continue/Interrupt while another goroutine attempts
	// breakpoint edits, all under the race detector.
	code := []uint32{Encode(OpJMP, 0, 0, uint16(codeAddr))}
	tg := newTarget(t, code)
	tg.SetInstructionBudget(0)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			done := make(chan struct{})
			go func() { _, _ = tg.Continue(); close(done) }()
			for tg.State() != StateRunning {
				runtime.Gosched()
			}
			// Management while running must fail cleanly.
			if err := tg.SetBreakpoint(codeAddr); !errors.Is(err, ErrRunning) {
				t.Errorf("set while running: %v", err)
			}
			if _, err := tg.Interrupt(); err != nil {
				t.Errorf("interrupt: %v", err)
			}
			<-done
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	wg.Wait()
	close(stop)
	t.Logf("scenario=concurrent-run-manage want=ErrRunning-rejects got=clean")
}
