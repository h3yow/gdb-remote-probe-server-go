// Package target implements a deterministic, in-process debuggable target:
// a tiny load/store virtual machine with protected memory and hardware
// breakpoints. It stands in for real probe hardware, so every result is
// reproducible from the input image.
//
// Instruction encoding (one little-endian u32, 4-byte aligned):
//
//	bits 31..24 opcode
//	bits 23..20 destination register (rd)
//	bits 19..16 source/second register (rs)
//	bits 15..0  immediate / address (I)
//
// Supported opcodes:
//
//	HALT  0x00            stop with ReasonTerminated
//	MOVI  0x01 rd = I
//	MOVR  0x02 rd = rs
//	ADD   0x03 rd = rd + rs
//	ADDI  0x04 rd = rd + I
//	LOAD  0x05 rd = u32[mem I]      (I must be 4-aligned, readable)
//	STORE 0x06 u32[mem I] = rs      (I must be 4-aligned, writable)
//	JMP   0x07 pc = I
//	JZ    0x08 if rd == 0 { pc = I } else { pc += 4 }
//	BRK   0x09 trap with ReasonBreakpoint (static breakpoint instruction)
//
// Dynamic breakpoints are data attached by the debugger, not patched bytes;
// they survive unchanged even while other state is inspected.
package target

import (
	"errors"
	"fmt"
	"sync"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/image"
)

// MaxBreakpoints is the hardware breakpoint slot limit.
const MaxBreakpoints = 4

// State of the target core.
type State uint8

// Core states.
const (
	StateHalted State = iota // stopped and accepting debug commands
	StateRunning
	StateTerminated
)

func (s State) String() string {
	switch s {
	case StateHalted:
		return "halted"
	case StateRunning:
		return "running"
	case StateTerminated:
		return "terminated"
	default:
		return "unknown"
	}
}

// Reason describes why the target halted.
type Reason uint8

// Halt reasons.
const (
	ReasonNone       Reason = iota
	ReasonPause             // interrupted by the debugger
	ReasonBreakpoint        // BRK instruction or dynamic breakpoint
	ReasonStep              // single step completed
	ReasonTerminated        // HALT executed
	ReasonFault             // memory/decode fault
)

func (r Reason) String() string {
	switch r {
	case ReasonNone:
		return "none"
	case ReasonPause:
		return "pause"
	case ReasonBreakpoint:
		return "breakpoint"
	case ReasonStep:
		return "step"
	case ReasonTerminated:
		return "terminated"
	case ReasonFault:
		return "fault"
	default:
		return "unknown"
	}
}

// FaultCode classifies a runtime fault so error classes stay distinguishable.
type FaultCode uint8

// Fault codes.
const (
	FaultNone FaultCode = iota
	FaultUnaligned
	FaultAccess
	FaultDecode
)

func (f FaultCode) String() string {
	switch f {
	case FaultNone:
		return "none"
	case FaultUnaligned:
		return "unaligned"
	case FaultAccess:
		return "access"
	case FaultDecode:
		return "decode"
	default:
		return "unknown"
	}
}

// Register count and aliases.
const (
	NumRegs   = 16
	RegPC     = 15
	RegZero   = 0
	RegResult = 1
)

// Opcodes.
const (
	OpHALT  = 0x00
	OpMOVI  = 0x01
	OpMOVR  = 0x02
	OpADD   = 0x03
	OpADDI  = 0x04
	OpLOAD  = 0x05
	OpSTORE = 0x06
	OpJMP   = 0x07
	OpJZ    = 0x08
	OpBRK   = 0x09
)

// BreakpointInfo describes one installed breakpoint.
type BreakpointInfo struct {
	Addr    uint32
	Enabled bool
	Hits    uint64
}

// HaltInfo is returned whenever execution stops.
type HaltInfo struct {
	Reason   Reason
	PC       uint32
	BPAddr   uint32 // valid when Reason == ReasonBreakpoint
	Fault    FaultCode
	FaultMsg string
}

// Sentinel errors for invalid debugger operations. Runtime instruction faults
// are reported through HaltInfo{Fault: ...}, not Go errors.
var (
	ErrRunning         = errors.New("target: target is running")
	ErrTerminated      = errors.New("target: target terminated")
	ErrInvalidRegister = errors.New("target: invalid register")
	ErrAlignment       = errors.New("target: address not aligned")
	ErrBPConflict      = errors.New("target: breakpoint already set at address")
	ErrBPLimit         = errors.New("target: breakpoint slot limit reached")
	ErrBPBadAddr       = errors.New("target: breakpoint address is not executable code")
	ErrNoBreakpoint    = errors.New("target: no breakpoint at address")
	ErrReadOnlyReg     = errors.New("target: register is read-only")
	ErrOutOfRange      = errors.New("target: memory access out of range")
	ErrBadPerm         = errors.New("target: permission denied")
	ErrIllegalInstr    = errors.New("target: illegal instruction")
)

// Target is the debuggable virtual machine. It is safe for concurrent method
// calls: the execution lock serializes core mutation.
type Target struct {
	mu sync.Mutex

	image     *image.Image
	regions   []image.Region
	entry     uint32
	regs      [NumRegs]uint32
	state     State
	lastHalt  HaltInfo
	breakpts  map[uint32]uint64 // addr -> hit count (presence == installed)
	bpEnabled map[uint32]bool

	// run is non-nil while a Continue loop owns the core.
	run *runHandle

	// budget bounds instructions per Continue (0 = unlimited, run until a
	// trap or interrupt). Defaults to a runaway guard.
	budget uint64
}

// runHandle coordinates one Continue execution with asynchronous Interrupts.
type runHandle struct {
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func (h *runHandle) cancel() { h.once.Do(func() { close(h.stop) }) }

// New creates a target from a parsed image. The image must define an executable
// region containing Entry. Identical images always yield identical initial
// state: PC = Entry, registers zeroed, no breakpoints.
func New(im *image.Image) (*Target, error) {
	if im == nil {
		return nil, errors.New("target: nil image")
	}
	if err := validateEntry(im); err != nil {
		return nil, err
	}
	t := &Target{
		image:     im,
		regions:   cloneRegions(im.Regions),
		entry:     im.Entry,
		breakpts:  make(map[uint32]uint64),
		bpEnabled: make(map[uint32]bool),
		budget:    1 << 20,
	}
	t.regs[RegPC] = im.Entry
	return t, nil
}

func validateEntry(im *image.Image) error {
	for _, rg := range im.Regions {
		if rg.Perm.Has(image.PermExecute) &&
			im.Entry >= rg.Addr && im.Entry < rg.Addr+uint32(len(rg.Data)) {
			if im.Entry%4 != 0 {
				return fmt.Errorf("%w: entry %#x unaligned", ErrAlignment, im.Entry)
			}
			return nil
		}
	}
	return fmt.Errorf("%w: entry %#x not in an executable region", ErrBadPerm, im.Entry)
}

func cloneRegions(in []image.Region) []image.Region {
	out := make([]image.Region, len(in))
	for i, rg := range in {
		cp := make([]byte, len(rg.Data))
		copy(cp, rg.Data)
		rg.Data = cp
		out[i] = rg
	}
	return out
}

// State returns the current core state.
func (t *Target) State() State {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

// PC returns the program counter.
func (t *Target) PC() uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.regs[RegPC]
}

// Entry returns the image entry point.
func (t *Target) Entry() uint32 { return t.entry }

// HaltInfo returns the most recent halt description.
func (t *Target) HaltInfo() HaltInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastHalt
}

// requireHaltedLocked checks the debugger-facing precondition.
func (t *Target) requireHaltedLocked() error {
	switch t.state {
	case StateRunning:
		return ErrRunning
	case StateTerminated:
		return ErrTerminated
	default:
		return nil
	}
}

// Regs returns a copy of all register values (PC is the last entry).
func (t *Target) Regs() ([]uint32, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.requireHaltedLocked(); err != nil {
		return nil, err
	}
	out := make([]uint32, NumRegs)
	copy(out, t.regs[:])
	return out, nil
}

// ReadReg reads one register.
func (t *Target) ReadReg(n int) (uint32, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n < 0 || n >= NumRegs {
		return 0, fmt.Errorf("%w: r%d", ErrInvalidRegister, n)
	}
	if err := t.requireHaltedLocked(); err != nil {
		return 0, err
	}
	return t.regs[n], nil
}

// WriteReg writes one register. The zero register and PC are read-only via
// this API (move execution with SetPC when needed); the value is validated
// before any change, so failures never partially mutate the register file.
func (t *Target) WriteReg(n int, v uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n < 0 || n >= NumRegs {
		return fmt.Errorf("%w: r%d", ErrInvalidRegister, n)
	}
	if err := t.requireHaltedLocked(); err != nil {
		return err
	}
	if n == RegZero {
		return fmt.Errorf("%w: r0", ErrReadOnlyReg)
	}
	t.regs[n] = v
	return nil
}

// SetPC relocates the program counter (still required to point at executable,
// 4-aligned code). It is the debugger's jump mechanism.
func (t *Target) SetPC(pc uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.requireHaltedLocked(); err != nil {
		return err
	}
	if pc%4 != 0 {
		return fmt.Errorf("%w: pc %#x", ErrAlignment, pc)
	}
	if _, err := t.fetchLocked(pc); err != nil {
		return err
	}
	t.regs[RegPC] = pc
	t.lastHalt = HaltInfo{}
	return nil
}

// findRegionLocked locates the region containing [addr, addr+n).
func (t *Target) findRegionLocked(addr uint32, n int) (*image.Region, error) {
	if n <= 0 {
		return nil, fmt.Errorf("%w: zero-length access", ErrOutOfRange)
	}
	start := uint64(addr)
	end := start + uint64(n)
	if end > 1<<32 {
		return nil, fmt.Errorf("%w: [%#x,%#x) wraps address space", ErrOutOfRange, addr, end)
	}
	for i := range t.regions {
		rg := &t.regions[i]
		lo := uint64(rg.Addr)
		hi := lo + uint64(len(rg.Data))
		if start >= lo && end <= hi {
			return rg, nil
		}
	}
	return nil, fmt.Errorf("%w: [%#x,+%d) not mapped", ErrOutOfRange, addr, n)
}

// isExecCodeLocked reports whether addr points at a 4-byte aligned instruction
// inside an executable region (decode legality is not required: breakpoints on
// padding/data words inside a code region still report "executable address").
func (t *Target) isExecCodeLocked(addr uint32) bool {
	if addr%4 != 0 {
		return false
	}
	for i := range t.regions {
		rg := &t.regions[i]
		if !rg.Perm.Has(image.PermExecute) {
			continue
		}
		lo := uint64(rg.Addr)
		hi := lo + uint64(len(rg.Data))
		if uint64(addr) >= lo && uint64(addr)+4 <= hi {
			return true
		}
	}
	return false
}

// ReadMem reads n bytes into a fresh slice; valid for halted or terminated
// targets (post-mortem inspection is allowed).
func (t *Target) ReadMem(addr uint32, n int) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state == StateRunning {
		return nil, ErrRunning
	}
	if addr%4 != 0 || n%4 != 0 {
		return nil, fmt.Errorf("%w: read %#x len %d", ErrAlignment, addr, n)
	}
	rg, err := t.findRegionLocked(addr, n)
	if err != nil {
		return nil, err
	}
	if !rg.Perm.Has(image.PermRead) {
		return nil, fmt.Errorf("%w: read of %q [%#x,+%d)", ErrBadPerm, rg.Name, addr, n)
	}
	off := int(addr - rg.Addr)
	out := make([]byte, n)
	copy(out, rg.Data[off:off+n])
	return out, nil
}

// WriteMem writes data atomically: every bound and permission check happens
// before the first byte is committed, so a rejected write leaves memory
// untouched even when the range spans multiple regions is rejected wholesale
// (cross-region writes are not allowed at all).
func (t *Target) WriteMem(addr uint32, data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.requireHaltedLocked(); err != nil {
		return err
	}
	n := len(data)
	if n == 0 {
		return nil
	}
	if addr%4 != 0 || n%4 != 0 {
		return fmt.Errorf("%w: write %#x len %d", ErrAlignment, addr, n)
	}
	rg, err := t.findRegionLocked(addr, n)
	if err != nil {
		return err
	}
	if !rg.Perm.Has(image.PermWrite) {
		return fmt.Errorf("%w: write of %q [%#x,+%d)", ErrBadPerm, rg.Name, addr, n)
	}
	// All checks passed: commit in one critical section.
	off := int(addr - rg.Addr)
	copy(rg.Data[off:off+n], data)
	return nil
}

// MemoryMap returns a snapshot of region metadata (addr, size, permissions).
type Segment struct {
	Name string
	Addr uint32
	Size int
	Perm image.Perm
}

// LookupSymbol resolves a symbol via the backing image. Stripped images and
// absent names return image.ErrSymbolNotFound.
func (t *Target) LookupSymbol(name string) (uint32, error) {
	t.mu.Lock()
	im := t.image
	t.mu.Unlock()
	sym, err := im.LookupSymbol(name)
	if err != nil {
		return 0, err
	}
	return sym.Addr, nil
}

// MemoryMap returns the static memory layout.
func (t *Target) MemoryMap() []Segment {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Segment, len(t.regions))
	for i, rg := range t.regions {
		out[i] = Segment{Name: rg.Name, Addr: rg.Addr, Size: len(rg.Data), Perm: rg.Perm}
	}
	return out
}

// Breakpoints returns info for all slots in ascending address order.
func (t *Target) Breakpoints() []BreakpointInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	addrs := make([]uint32, 0, len(t.breakpts))
	for a := range t.breakpts {
		addrs = append(addrs, a)
	}
	// simple sort to avoid import churn
	for i := 1; i < len(addrs); i++ {
		for j := i; j > 0 && addrs[j-1] > addrs[j]; j-- {
			addrs[j-1], addrs[j] = addrs[j], addrs[j-1]
		}
	}
	out := make([]BreakpointInfo, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, BreakpointInfo{
			Addr:    a,
			Enabled: t.bpEnabled[a],
			Hits:    t.breakpts[a],
		})
	}
	return out
}

// SetBreakpoint installs a hardware breakpoint. Idempotent: setting the same
// address again succeeds and changes nothing (hit counts preserved). Distinct
// errors cover alignment, non-code addresses and the slot limit.
func (t *Target) SetBreakpoint(addr uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.requireHaltedLocked(); err != nil {
		return err
	}
	if _, ok := t.breakpts[addr]; ok {
		return nil // idempotent
	}
	if addr%4 != 0 {
		return fmt.Errorf("%w: %#x", ErrAlignment, addr)
	}
	if !t.isExecCodeLocked(addr) {
		return fmt.Errorf("%w: %#x is not executable code", ErrBPBadAddr, addr)
	}
	if len(t.breakpts) >= MaxBreakpoints {
		return fmt.Errorf("%w: %d slots, want %#x", ErrBPLimit, MaxBreakpoints, addr)
	}
	t.breakpts[addr] = 0
	t.bpEnabled[addr] = true
	return nil
}

// ClearBreakpoint removes a breakpoint. Idempotent: clearing an absent address
// returns ErrNoBreakpoint on first call; callers that want set/clear symmetry
// use ClearBreakpointIfExists.
func (t *Target) ClearBreakpoint(addr uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.requireHaltedLocked(); err != nil {
		return err
	}
	if _, ok := t.breakpts[addr]; !ok {
		return fmt.Errorf("%w: %#x", ErrNoBreakpoint, addr)
	}
	delete(t.breakpts, addr)
	delete(t.bpEnabled, addr)
	return nil
}

// Reset returns the target to the exact power-on state derived from the image:
// image memory bytes, zeroed registers, PC=Entry, no breakpoints or hits.
func (t *Target) Reset() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state == StateRunning {
		return ErrRunning
	}
	t.regions = cloneRegions(t.image.Regions)
	t.regs = [NumRegs]uint32{}
	t.regs[RegPC] = t.entry
	t.breakpts = make(map[uint32]uint64)
	t.bpEnabled = make(map[uint32]bool)
	t.state = StateHalted
	t.lastHalt = HaltInfo{}
	t.run = nil
	return nil
}

// SetInstructionBudget sets the per-Continue instruction cap. Pass 0 for
// unlimited execution (run until a trap, fault or explicit interrupt),
// which is what loop/interrupt tests need.
func (t *Target) SetInstructionBudget(n uint64) {
	t.mu.Lock()
	t.budget = n
	t.mu.Unlock()
}

// Close stops any running execution and marks the target terminated.
func (t *Target) Close() error {
	t.mu.Lock()
	run := t.run
	t.mu.Unlock()
	if run != nil {
		run.cancel()
		<-run.done
	}
	t.mu.Lock()
	t.run = nil
	t.state = StateTerminated
	t.lastHalt = HaltInfo{Reason: ReasonTerminated, PC: t.regs[RegPC]}
	t.mu.Unlock()
	return nil
}
