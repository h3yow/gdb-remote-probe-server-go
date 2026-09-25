package target

import (
	"os"
	"path/filepath"
	"testing"
)

func testImage(t *testing.T, stripped bool) *Image {
	t.Helper()
	// .text @0x0000: movi r0,1; movi r1,3; add r2,r1,r0; st 0x20,r2; loop: jmp loop
	// .data @0x0020: 4 zero bytes
	p := NewProgram().
		Movi(RegR0, 1).
		Movi(RegR1, 3).
		Add(RegR2, RegR1, RegR0).
		St(0x20, RegR2).
		Label("loop").
		Jmp("loop")
	img, err := BuildImage(p, 0x0000, 0x0020, []byte{0, 0, 0, 0}, stripped)
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	return img
}

func TestRoundTripImage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.img")
	img := testImage(t, false)
	if err := WriteImage(path, img); err != nil {
		t.Fatalf("WriteImage: %v", err)
	}
	got, err := ReadImage(path)
	if err != nil {
		t.Fatalf("ReadImage: %v", err)
	}
	if got.Entry != 0 {
		t.Fatalf("entry = %#x", got.Entry)
	}
	sym, err := got.LookupSymbol("loop")
	if err != nil {
		t.Fatalf("LookupSymbol: %v", err)
	}
	if sym.Addr != 4*InstSize {
		t.Fatalf("loop addr = %#x", sym.Addr)
	}
}

func TestStrippedImageStillLoads(t *testing.T) {
	img := testImage(t, true)
	if !img.Stripped {
		t.Fatal("want stripped image")
	}
	if _, err := img.LookupSymbol("loop"); CodeOf(err) != CodeSymbolNotFound {
		t.Fatalf("want CodeSymbolNotFound, got %v", err)
	}
	tg, err := NewTarget(img, DefaultOptions())
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	if r, err := tg.Step(); err != nil || r.Kind != StopNone {
		t.Fatalf("step stripped target: reason=%v err=%v", r, err)
	}
}

func TestCorruptionErrorCodes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.img")
	if err := WriteImage(path, testImage(t, false)); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)

	cases := []struct {
		name string
		mut  func(b []byte) []byte
		want Code
	}{
		{"truncated", func(b []byte) []byte { return b[:8] }, CodeImageTooShort},
		{"bad magic", func(b []byte) []byte { b[0] = 'X'; return b }, CodeBadMagic},
		{"bad version", func(b []byte) []byte { b[8] = 99; return b }, CodeUnsupportedVersion},
		{"bad length", func(b []byte) []byte { b[12]++; return b }, CodeImageCorrupt},
		{"bad checksum", func(b []byte) []byte { b[len(b)-1] ^= 0xFF; return b }, CodeBadChecksum},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".img")
			if err := os.WriteFile(p, tc.mut(append([]byte(nil), raw...)), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := ReadImage(p)
			if CodeOf(err) != tc.want {
				t.Fatalf("want code %d, got %v", tc.want, err)
			}
		})
	}
}

func TestMemoryProtection(t *testing.T) {
	tg, err := NewTarget(testImage(t, true), DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	// out of range
	if _, err := tg.ReadMemory(0x9000, 4); CodeOf(err) != CodeAddressOutOfRange {
		t.Fatalf("want OOR read, got %v", err)
	}
	// write into R-X .text
	if err := tg.WriteMemory(0, []byte{1, 2, 3, 4}); CodeOf(err) != CodeReadOnly {
		t.Fatalf("want read-only, got %v", err)
	}
	// read from data, then write
	if _, err := tg.ReadMemory(0x20, 4); err != nil {
		t.Fatalf("read data: %v", err)
	}
	if err := tg.WriteMemory(0x20, []byte{9, 9, 9, 9}); err != nil {
		t.Fatalf("write data: %v", err)
	}
	// partial-range write must fail atomically; preexisting bytes unchanged
	err = tg.WriteMemory(0x22, []byte{1, 2, 3, 4}) // crosses 0x24 unmapped
	if CodeOf(err) != CodeAddressOutOfRange {
		t.Fatalf("want cross-segment OOR, got %v", err)
	}
	got, _ := tg.ReadMemory(0x20, 4)
	if string(got) != string([]byte{9, 9, 9, 9}) {
		t.Fatalf("partial write leaked: %v", got)
	}
}

func TestStepConsistency(t *testing.T) {
	tg, _ := NewTarget(testImage(t, true), DefaultOptions())
	for i := 0; i < 4; i++ {
		if _, err := tg.Step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	r2, _ := tg.ReadRegister(RegR2)
	if r2 != 4 {
		t.Fatalf("r2 = %d, want 4", r2)
	}
	mem, _ := tg.ReadMemory(0x20, 4)
	if mem[0] != 4 {
		t.Fatalf("stored value = %d", mem[0])
	}
	// next instruction is jmp-to-self: stepping lands on same PC, no breakpoint
	pc, _ := tg.ReadRegister(RegPC)
	if _, err := tg.Step(); err != nil {
		t.Fatalf("step jmp: %v", err)
	}
	pc2, _ := tg.ReadRegister(RegPC)
	if pc2 != pc {
		t.Fatalf("pc after self jmp = %#x want %#x", pc2, pc)
	}
}

func TestBreakpointIdempotentAndBoundaries(t *testing.T) {
	tg, _ := NewTarget(testImage(t, true), Options{MaxBreakpoints: 2})
	bp1, err := tg.SetBreakpoint(0x04)
	if err != nil {
		t.Fatal(err)
	}
	bp1dup, err := tg.SetBreakpoint(0x04)
	if err != nil || bp1dup.Addr != bp1.Addr {
		t.Fatalf("repeat set not idempotent: %v", err)
	}
	if _, err := tg.SetBreakpoint(0x08); err != nil {
		t.Fatal(err)
	}
	if _, err := tg.SetBreakpoint(0x0c); CodeOf(err) != CodeBreakpointLimit {
		t.Fatalf("want limit, got %v", err)
	}
	if _, err := tg.SetBreakpoint(0x03); CodeOf(err) != CodeMisaligned {
		t.Fatalf("want misaligned, got %v", err)
	}
	if _, err := tg.SetBreakpoint(0x20); CodeOf(err) != CodeNotExecutable {
		t.Fatalf("want not executable, got %v", err)
	}
	if err := tg.ClearBreakpoint(0x04); err != nil {
		t.Fatal(err)
	}
	if err := tg.ClearBreakpoint(0x04); err != nil { // idempotent clear
		t.Fatalf("repeat clear: %v", err)
	}
}

func TestResumeInterruptAndHits(t *testing.T) {
	tg, _ := NewTarget(testImage(t, true), DefaultOptions())
	if _, err := tg.SetBreakpoint(0x04); err != nil {
		t.Fatal(err)
	}
	// continue: stops at breakpoint (2nd instruction)
	if err := tg.Resume(); err != nil {
		t.Fatal(err)
	}
	r := tg.WaitStopped()
	if r.Kind != StopBreakpoint || r.PC != 0x04 || r.Hits != 1 {
		t.Fatalf("stop = %+v", r)
	}
	// continue again: step-over leaves the breakpoint, loop never returns to it
	if err := tg.Resume(); err != nil {
		t.Fatal(err)
	}
	if err := tg.Interrupt(); err != nil {
		t.Fatal(err)
	}
	r = tg.WaitStopped()
	if r.Kind != StopInterrupt {
		t.Fatalf("want interrupt, got %+v", r)
	}
	// running-state mutations are rejected
	if err := tg.Resume(); err != nil {
		t.Fatal(err)
	}
	if err := tg.WriteMemory(0x20, []byte{0}); CodeOf(err) != CodeTargetRunning {
		t.Fatalf("want running reject, got %v", err)
	}
	if _, err := tg.SetBreakpoint(0x08); CodeOf(err) != CodeTargetRunning {
		t.Fatalf("want running reject bp, got %v", err)
	}
	if err := tg.Interrupt(); err != nil {
		t.Fatal(err)
	}
	// second interrupt after stop is harmless
	if err := tg.Interrupt(); err != nil {
		t.Fatalf("redundant interrupt: %v", err)
	}
}

func TestHaltAndIllegalFault(t *testing.T) {
	p := NewProgram().Movi(RegR0, 0).Bz(RegR0, "ill").Label("ill").Ill()
	img, err := BuildImage(p, 0, 0x100, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	tg, _ := NewTarget(img, DefaultOptions())
	r, err := tg.Step() // movi
	if err != nil {
		t.Fatal(err)
	}
	_ = r
	r, err = tg.Step() // bz taken: lands on ill at 0x04 (no breakpoint, no fault until executed)
	if err != nil {
		t.Fatalf("branch step: %v", err)
	}
	r, err = tg.Step() // execute ill
	if err == nil || CodeOf(err) != CodeNotExecutable || r.Kind != StopFault {
		t.Fatalf("want fault on ill, reason=%+v err=%v", r, err)
	}
	// halted/faulted target refuses further run requests
	if _, err := tg.Step(); CodeOf(err) != CodeNotExecutable {
		t.Fatalf("want halted step reject, got %v", err)
	}
	if err := tg.Resume(); CodeOf(err) != CodeNotExecutable {
		t.Fatalf("want halted resume reject, got %v", err)
	}
	// reset makes it usable again
	if err := tg.Reset(); err != nil {
		t.Fatal(err)
	}
	pc, _ := tg.ReadRegister(RegPC)
	if pc != 0 {
		t.Fatalf("pc after reset = %#x", pc)
	}

	// explicit halt program
	p2 := NewProgram().Halt()
	img2, _ := BuildImage(p2, 0, 0x100, nil, true)
	tg2, _ := NewTarget(img2, DefaultOptions())
	r2, stepErr := tg2.Step()
	if stepErr == nil || CodeOf(stepErr) != CodeTargetHalted || r2.Kind != StopHalt {
		t.Fatalf("halt: reason=%+v err=%v", r2, stepErr)
	}
}

func TestRegisterIndexValidation(t *testing.T) {
	tg, _ := NewTarget(testImage(t, true), DefaultOptions())
	if _, err := tg.ReadRegister(RegN); CodeOf(err) != CodeRegisterIndex {
		t.Fatal("want register index error")
	}
	if err := tg.WriteRegister(-1, 1); CodeOf(err) != CodeRegisterIndex {
		t.Fatal("want register index error")
	}
}
