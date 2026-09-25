package target

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/image"
)

const (
	codeAddr = uint32(0x1000)
	ramAddr  = uint32(0x2000)
)

func buildImage(t *testing.T, code []uint32, ramSize int, stripped bool) *image.Image {
	t.Helper()
	cb := make([]byte, len(code)*4)
	for i, w := range code {
		cb[i*4] = byte(w)
		cb[i*4+1] = byte(w >> 8)
		cb[i*4+2] = byte(w >> 16)
		cb[i*4+3] = byte(w >> 24)
	}
	raw, err := image.NewBuilder().
		Entry(codeAddr).
		Region(image.Region{Name: "flash", Addr: codeAddr, Data: cb, Perm: image.PermRead | image.PermExecute}).
		Region(image.Region{Name: "ram", Addr: ramAddr, Data: make([]byte, ramSize), Perm: image.PermRead | image.PermWrite}).
		Symbol(image.Symbol{Name: "main", Addr: codeAddr, Size: uint32(len(cb))}).
		Stripped(stripped).
		Build()
	if err != nil {
		t.Fatalf("build image: %v", err)
	}
	im, err := image.Load(raw)
	if err != nil {
		t.Fatalf("load image: %v", err)
	}
	return im
}

func newTarget(t *testing.T, code []uint32) *Target {
	t.Helper()
	tg, err := New(buildImage(t, code, 16, false))
	if err != nil {
		t.Fatalf("new target: %v", err)
	}
	t.Cleanup(func() { _ = tg.Close() })
	return tg
}

func TestNewTargetInitialView(t *testing.T) {
	tg := newTarget(t, []uint32{Encode(OpHALT, 0, 0, 0)})
	if tg.PC() != codeAddr || tg.State() != StateHalted {
		t.Fatalf("initial pc/state wrong: %#x %s", tg.PC(), tg.State())
	}
	regs, _ := tg.Regs()
	for i, v := range regs {
		if i == RegPC {
			if v != codeAddr {
				t.Fatalf("pc=%#x want entry", v)
			}
			continue
		}
		if v != 0 {
			t.Fatalf("r%d nonzero initially", i)
		}
	}
}

func TestNewTargetEntryValidation(t *testing.T) {
	raw, err := image.NewBuilder().
		Entry(0x9999).
		Region(image.Region{Name: "flash", Addr: codeAddr, Data: []byte{0, 0, 0, 0}, Perm: image.PermRead | image.PermExecute}).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	im, _ := image.Load(raw)
	if _, err := New(im); !errors.Is(err, ErrBadPerm) {
		t.Fatalf("want ErrBadPerm, got %v", err)
	}
}

func TestStepMOVIADDHalt(t *testing.T) {
	code := []uint32{
		Encode(OpMOVI, 1, 0, 7),  // r1 = 7
		Encode(OpMOVI, 2, 0, 35), // r2 = 35
		Encode(OpADD, 1, 2, 0),   // r1 += r2
		Encode(OpHALT, 0, 0, 0),
	}
	tg := newTarget(t, code)
	mustStep := func(wantPC uint32) {
		t.Helper()
		info, err := tg.Step()
		if err != nil || info.Reason != ReasonStep || info.PC != wantPC {
			t.Fatalf("step: %+v err=%v", info, err)
		}
	}
	mustStep(codeAddr + 4)
	mustStep(codeAddr + 8)
	mustStep(codeAddr + 12)
	if v, _ := tg.ReadReg(1); v != 42 {
		t.Fatalf("r1=%d want 42", v)
	}
	info, err := tg.Step()
	if err != nil || info.Reason != ReasonTerminated {
		t.Fatalf("halt: %+v %v", info, err)
	}
	if tg.State() != StateTerminated {
		t.Fatal("state not terminated")
	}
}

func TestZeroRegisterReadOnly(t *testing.T) {
	tg := newTarget(t, []uint32{Encode(OpHALT, 0, 0, 0)})
	if err := tg.WriteReg(RegZero, 9); !errors.Is(err, ErrReadOnlyReg) {
		t.Fatalf("want ErrReadOnlyReg, got %v", err)
	}
	if err := tg.WriteReg(-1, 1); !errors.Is(err, ErrInvalidRegister) {
		t.Fatalf("want ErrInvalidRegister, got %v", err)
	}
	if err := tg.WriteReg(NumRegs, 1); !errors.Is(err, ErrInvalidRegister) {
		t.Fatalf("want ErrInvalidRegister, got %v", err)
	}
}

func TestMemoryReadWrite(t *testing.T) {
	tg := newTarget(t, []uint32{Encode(OpHALT, 0, 0, 0)})
	if err := tg.WriteMem(ramAddr, []byte{1, 2, 3, 4}); err != nil {
		t.Fatalf("write ram: %v", err)
	}
	got, err := tg.ReadMem(ramAddr, 4)
	if err != nil || !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Fatalf("readback: %x %v", got, err)
	}
	// read-only flash write
	if err := tg.WriteMem(codeAddr, []byte{0, 0, 0, 0}); !errors.Is(err, ErrBadPerm) {
		t.Fatalf("want ErrBadPerm, got %v", err)
	}
	// out of range
	if _, err := tg.ReadMem(0x3000, 4); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("want ErrOutOfRange, got %v", err)
	}
	// unaligned
	if err := tg.WriteMem(ramAddr+1, []byte{0}); !errors.Is(err, ErrAlignment) {
		t.Fatalf("want ErrAlignment, got %v", err)
	}
}

func TestFailedWriteIsAtomic(t *testing.T) {
	tg := newTarget(t, []uint32{Encode(OpHALT, 0, 0, 0)})
	before, _ := tg.ReadMem(ramAddr, 8)
	// span end beyond region
	if err := tg.WriteMem(ramAddr+12, []byte{1, 2, 3, 4, 5, 6, 7, 8}); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("want ErrOutOfRange, got %v", err)
	}
	after, _ := tg.ReadMem(ramAddr, 8)
	if !bytes.Equal(before, after) {
		t.Fatal("memory partially modified by rejected write")
	}
	// flash bytes must also be untouched
	flash, _ := tg.ReadMem(codeAddr, 4)
	if !bytes.Equal(flash, []byte{0, 0, 0, 0}) {
		t.Fatal("flash mutated")
	}
}

func TestBreakpoints(t *testing.T) {
	code := []uint32{
		Encode(OpMOVI, 1, 0, 1),
		Encode(OpMOVI, 2, 0, 2),
		Encode(OpMOVI, 3, 0, 3),
		Encode(OpMOVI, 4, 0, 4),
		Encode(OpHALT, 0, 0, 0),
	}
	tg := newTarget(t, code)

	if err := tg.SetBreakpoint(codeAddr + 4); err != nil {
		t.Fatalf("set bp: %v", err)
	}
	// idempotent repeat
	if err := tg.SetBreakpoint(codeAddr + 4); err != nil {
		t.Fatalf("repeat set: %v", err)
	}
	if len(tg.Breakpoints()) != 1 {
		t.Fatal("repeat set duplicated slot")
	}
	// unaligned
	if err := tg.SetBreakpoint(codeAddr + 1); !errors.Is(err, ErrAlignment) {
		t.Fatalf("want ErrAlignment, got %v", err)
	}
	// non-code
	if err := tg.SetBreakpoint(ramAddr); !errors.Is(err, ErrBPBadAddr) {
		t.Fatalf("want ErrBPBadAddr, got %v", err)
	}
	// fill the remaining slots, then expect limit
	for _, a := range []uint32{codeAddr, codeAddr + 8, codeAddr + 12} {
		if err := tg.SetBreakpoint(a); err != nil {
			t.Fatalf("set %#x: %v", a, err)
		}
	}
	if err := tg.SetBreakpoint(codeAddr + 16); !errors.Is(err, ErrBPLimit) {
		t.Fatalf("want ErrBPLimit, got %v", err)
	}

	info, err := tg.Continue()
	if err != nil || info.Reason != ReasonBreakpoint || info.BPAddr != codeAddr {
		t.Fatalf("continue hit first bp: %+v %v", info, err)
	}
	// hits recorded
	var hits uint64
	for _, b := range tg.Breakpoints() {
		if b.Addr == codeAddr {
			hits = b.Hits
		}
	}
	if hits != 1 {
		t.Fatalf("hits=%d want 1", hits)
	}

	// clear + idempotent error
	if err := tg.ClearBreakpoint(codeAddr); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if err := tg.ClearBreakpoint(codeAddr); !errors.Is(err, ErrNoBreakpoint) {
		t.Fatalf("want ErrNoBreakpoint, got %v", err)
	}
}

func TestStepOverBreakpointDoesNotCount(t *testing.T) {
	code := []uint32{Encode(OpMOVI, 1, 0, 1), Encode(OpHALT, 0, 0, 0)}
	tg := newTarget(t, code)
	if err := tg.SetBreakpoint(codeAddr); err != nil {
		t.Fatal(err)
	}
	if info, err := tg.Step(); err != nil || info.Reason != ReasonStep {
		t.Fatalf("step should step over bp: %+v %v", info, err)
	}
	for _, b := range tg.Breakpoints() {
		if b.Hits != 0 {
			t.Fatalf("step incremented hits: %d", b.Hits)
		}
	}
}

func TestStaticBRKInstruction(t *testing.T) {
	code := []uint32{Encode(OpBRK, 0, 0, 0), Encode(OpHALT, 0, 0, 0)}
	tg := newTarget(t, code)
	info, err := tg.Continue()
	if err != nil || info.Reason != ReasonBreakpoint || info.PC != codeAddr {
		t.Fatalf("brk: %+v %v", info, err)
	}
}

func TestRuntimeFaults(t *testing.T) {
	// STORE into flash: r1=value(5), store immediate addr=codeAddr
	code := []uint32{
		Encode(OpMOVI, 1, 0, 5),
		Encode(OpSTORE, 0, 1, uint16(codeAddr)),
	}
	tg := newTarget(t, code)
	info, err := tg.Continue()
	if err != nil {
		t.Fatal(err)
	}
	if info.Reason != ReasonFault || info.Fault != FaultAccess {
		t.Fatalf("want access fault, got %+v", info)
	}
	if info.PC != codeAddr+4 {
		t.Fatalf("fault PC=%#x", info.PC)
	}
	// PC and regs inspectable after fault
	if v, _ := tg.ReadReg(1); v != 5 {
		t.Fatalf("r1 after fault: %d", v)
	}
}

func TestRunningRejectsDebugOps(t *testing.T) {
	// tight loop: jmp to self
	code := []uint32{Encode(OpJMP, 0, 0, uint16(codeAddr))}
	tg := newTarget(t, code)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = tg.Continue() }()

	// Yield until the Continue goroutine has entered running state. Gosched
	// is a scheduler yield, not a timed sleep, so timing stays deterministic.
	for i := 0; i < 100000; i++ {
		if tg.State() == StateRunning {
			break
		}
		runtime.Gosched()
	}
	if tg.State() != StateRunning {
		t.Fatal("target never entered running state")
	}
	if _, err := tg.Regs(); !errors.Is(err, ErrRunning) {
		t.Fatalf("regs while running: %v", err)
	}
	if err := tg.WriteReg(1, 1); !errors.Is(err, ErrRunning) {
		t.Fatalf("write reg while running: %v", err)
	}
	if err := tg.WriteMem(ramAddr, []byte{1, 2, 3, 4}); !errors.Is(err, ErrRunning) {
		t.Fatalf("write mem while running: %v", err)
	}
	if err := tg.SetBreakpoint(codeAddr + 4); !errors.Is(err, ErrRunning) {
		t.Fatalf("set bp while running: %v", err)
	}
	info, err := tg.Interrupt()
	if err != nil || info.Reason != ReasonPause {
		t.Fatalf("interrupt: %+v %v", info, err)
	}
	wg.Wait()
	if tg.State() != StateHalted {
		t.Fatalf("state after interrupt: %s", tg.State())
	}
}

func TestInterruptViaContext(t *testing.T) {
	code := []uint32{Encode(OpJMP, 0, 0, uint16(codeAddr))}
	tg := newTarget(t, code)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan HaltInfo, 1)
	go func() {
		info, _ := tg.ContinueCtx(ctx)
		done <- info
	}()
	for i := 0; i < 100000; i++ {
		if tg.State() == StateRunning {
			break
		}
		runtime.Gosched()
	}
	cancel()
	info := <-done
	if info.Reason != ReasonPause {
		t.Fatalf("want pause, got %+v", info)
	}
}

func TestResetRestoresImage(t *testing.T) {
	code := []uint32{Encode(OpMOVI, 1, 0, 9), Encode(OpHALT, 0, 0, 0)}
	tg := newTarget(t, code)
	_, _ = tg.Step()
	_ = tg.WriteMem(ramAddr, []byte{9, 9, 9, 9})
	_ = tg.SetBreakpoint(codeAddr)
	if err := tg.Reset(); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if tg.PC() != codeAddr || tg.State() != StateHalted {
		t.Fatal("reset pc/state wrong")
	}
	if v, _ := tg.ReadReg(1); v != 0 {
		t.Fatal("regs not zeroed")
	}
	if got, _ := tg.ReadMem(ramAddr, 4); !bytes.Equal(got, []byte{0, 0, 0, 0}) {
		t.Fatalf("ram not restored: %x", got)
	}
	if len(tg.Breakpoints()) != 0 {
		t.Fatal("breakpoints survived reset")
	}
}

func TestDeterministicRecreate(t *testing.T) {
	im := buildImage(t, []uint32{Encode(OpMOVI, 1, 0, 42), Encode(OpHALT, 0, 0, 0)}, 16, true)
	a, _ := New(im)
	b, _ := New(im)
	ar, _ := a.Regs()
	br, _ := b.Regs()
	if !equalU32(ar, br) {
		t.Fatal("register views differ")
	}
	am, _ := a.ReadMem(codeAddr, 8)
	bm, _ := b.ReadMem(codeAddr, 8)
	if !bytes.Equal(am, bm) {
		t.Fatal("memory views differ")
	}
}

func equalU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
