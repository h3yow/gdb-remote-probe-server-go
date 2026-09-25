package target

import (
	"fmt"
	"sort"
	"sync"
)

// Register layout of the virtual machine.
const (
	RegR0 = 0
	RegR1 = 1
	RegR2 = 2
	RegR3 = 3
	RegR4 = 4
	RegR5 = 5
	RegR6 = 6
	RegR7 = 7
	RegPC = 8
	RegN  = 9 // number of registers: r0..r7 + pc

	RegSize = 4
)

// Instruction width and breakpoint alignment.
const InstSize = uint32(4)

// StopKind classifies why the target stopped.
type StopKind int

const (
	StopNone StopKind = iota
	StopHalt
	StopBreakpoint
	StopInterrupt
	StopFault
)

func (k StopKind) String() string {
	switch k {
	case StopHalt:
		return "halt"
	case StopBreakpoint:
		return "breakpoint"
	case StopInterrupt:
		return "interrupt"
	case StopFault:
		return "fault"
	default:
		return "none"
	}
}

// StopReason describes the terminal state of a step or continue.
type StopReason struct {
	Kind StopKind
	PC   uint32
	// Detail carries the structured fault error for StopFault.
	Detail error
	// Hits is the breakpoint hit count when Kind == StopBreakpoint.
	Hits uint64
}

// Breakpoint is an executable-address breakpoint.
type Breakpoint struct {
	Addr uint32
	Hits uint64
}

// Options configures a Target.
type Options struct {
	MaxBreakpoints int
	// StepBudget caps the number of instructions a single Resume may
	// execute before failing deterministically. Zero disables the cap.
	StepBudget uint64
}

// DefaultMaxBreakpoints is the hardware-style breakpoint capacity.
const DefaultMaxBreakpoints = 4

// DefaultOptions returns the default target configuration.
func DefaultOptions() Options {
	return Options{MaxBreakpoints: DefaultMaxBreakpoints, StepBudget: 1_000_000}
}

// Target is a single debuggable execution context. All exported methods
// are safe for concurrent use; mutating operations while the target is
// running fail with CodeTargetRunning without partial modification.
type Target struct {
	mu sync.Mutex

	image *Image
	opts  Options

	mem      []byte // flat shadow spanning lowest..highest mapped byte
	base     uint32 // address corresponding to mem[0]
	segIndex []int  // per-byte segment index (-1 unmapped)
	segPerm  []Perm // per-byte permission cache

	regs [RegN]uint32

	breakpoints map[uint32]*Breakpoint

	running bool
	stop    StopReason

	stopReq chan struct{}
	doneCh  chan struct{}
	started chan struct{} // closed once the run loop first observes running state
}

// NewTarget constructs a target from a parsed image. The image is copied,
// so later mutation of the caller's image never affects the target.
func NewTarget(img *Image, opts Options) (*Target, error) {
	const op = "NewTarget"
	if img == nil {
		return nil, newError(CodeImageCorrupt, op, "nil image")
	}
	if err := img.validate(op); err != nil {
		return nil, err
	}
	if opts.MaxBreakpoints == 0 {
		opts = DefaultOptions()
	}
	t := &Target{
		image:       img.clone(),
		opts:        opts,
		breakpoints: make(map[uint32]*Breakpoint),
		stopReq:     make(chan struct{}),
		doneCh:      make(chan struct{}),
	}
	if err := t.loadMemory(); err != nil {
		return nil, err
	}
	t.hardReset()
	return t, nil
}

// loadMemory builds the flat shadow and per-byte permission/index tables.
func (t *Target) loadMemory() error {
	const op = "loadMemory"
	var lo, hi uint64 = ^uint64(0), 0
	for i := range t.image.Segments {
		s := &t.image.Segments[i]
		if uint64(s.Addr) < lo {
			lo = uint64(s.Addr)
		}
		end, _ := s.end()
		if uint64(end) > hi {
			hi = uint64(end)
		}
	}
	if hi <= lo {
		return newError(CodeImageCorrupt, op, "empty address coverage")
	}
	size := hi - lo
	if size > 256*1024*1024 {
		return newError(CodeImageCorrupt, op, fmt.Sprintf("address coverage too large: %d bytes", size))
	}
	t.base = uint32(lo)
	t.mem = make([]byte, size)
	t.segIndex = make([]int, size)
	t.segPerm = make([]Perm, size)
	for i := range t.segIndex {
		t.segIndex[i] = -1
	}
	for i := range t.image.Segments {
		s := &t.image.Segments[i]
		off := uint64(s.Addr) - lo
		copy(t.mem[off:off+uint64(len(s.Data))], s.Data)
		for j := 0; j < len(s.Data); j++ {
			t.segPerm[off+uint64(j)] = s.Perm
			t.segIndex[off+uint64(j)] = i
		}
	}
	return nil
}

// hardReset restores the image contents, zeroes registers, clears
// breakpoints and reinitialises run signalling. Caller holds no lock
// (used by constructor) or the lock.
func (t *Target) hardReset() {
	// restore segment contents into the shadow
	for i := range t.image.Segments {
		s := &t.image.Segments[i]
		off := uint64(s.Addr) - uint64(t.base)
		copy(t.mem[off:off+uint64(len(s.Data))], s.Data)
	}
	t.regs = [RegN]uint32{}
	t.regs[RegPC] = t.image.Entry
	t.breakpoints = make(map[uint32]*Breakpoint)
	t.running = false
	t.stop = StopReason{}
	t.stopReq = make(chan struct{})
	// doneCh starts closed: a fresh target is stopped.
	t.doneCh = make(chan struct{})
	close(t.doneCh)
	t.started = nil
}

// State is a point-in-time snapshot of target state.
type State struct {
	Running     bool
	Regs        [RegN]uint32
	Breakpoints []Breakpoint
	Stop        StopReason
}

// StateSnapshot returns a detached copy of the observable state.
func (t *Target) StateSnapshot() State {
	t.mu.Lock()
	defer t.mu.Unlock()
	return State{
		Running:     t.running,
		Regs:        t.regs,
		Breakpoints: t.sortedBreakpointsLocked(),
		Stop:        t.stop,
	}
}

// IsRunning reports whether the target is currently executing.
func (t *Target) IsRunning() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}

// Image returns the parsed image the target was built from.
func (t *Target) Image() *Image { return t.image }

// Reset restores the image, zeroes registers (PC = entry) and clears all
// breakpoints. Fails while running.
func (t *Target) Reset() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return newError(CodeTargetRunning, "Reset", "cannot reset while running")
	}
	t.hardReset()
	return nil
}

// checkRange validates a [addr, addr+n) access: fully mapped and matching
// permission for every byte. It never mutates state.
func (t *Target) checkRange(op string, addr uint32, n int, want Perm) error {
	if n < 0 {
		return newError(CodeAddressOutOfRange, op, "negative length")
	}
	start := uint64(addr)
	end := start + uint64(n)
	if end > 0x100000000 {
		return newError(CodeAddressOutOfRange, op,
			fmt.Sprintf("range [0x%08x,+%d) overflows address space", addr, n))
	}
	for a := start; a < end; a++ {
		off := int(a - uint64(t.base))
		if off < 0 || off >= len(t.mem) || t.segIndex[off] < 0 {
			return newError(CodeAddressOutOfRange, op,
				fmt.Sprintf("address 0x%08x is not mapped", uint32(a)))
		}
		if t.segPerm[off]&want == 0 {
			switch want {
			case PermWrite:
				return newError(CodeReadOnly, op,
					fmt.Sprintf("address 0x%08x is not writable", uint32(a)))
			case PermExec:
				return newError(CodeNotExecutable, op,
					fmt.Sprintf("address 0x%08x is not executable", uint32(a)))
			default:
				return newError(CodeAddressOutOfRange, op,
					fmt.Sprintf("address 0x%08x lacks read permission", uint32(a)))
			}
		}
	}
	return nil
}

// ReadMemory returns a copy of n bytes starting at addr. Every byte must
// be mapped and readable.
func (t *Target) ReadMemory(addr, length uint32) ([]byte, error) {
	const op = "ReadMemory"
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkRange(op, addr, int(length), PermRead); err != nil {
		return nil, err
	}
	off := uint64(addr) - uint64(t.base)
	out := make([]byte, length)
	copy(out, t.mem[off:off+uint64(length)])
	return out, nil
}

// WriteMemory writes data atomically: the whole range is validated before
// any byte changes, so a failure never causes a partial write.
func (t *Target) WriteMemory(addr uint32, data []byte) error {
	const op = "WriteMemory"
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return newError(CodeTargetRunning, op, "cannot write memory while running")
	}
	if err := t.checkRange(op, addr, len(data), PermWrite); err != nil {
		return err
	}
	off := uint64(addr) - uint64(t.base)
	copy(t.mem[off:off+uint64(len(data))], data)
	return nil
}

// ReadRegister returns one register value.
func (t *Target) ReadRegister(i int) (uint32, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if i < 0 || i >= RegN {
		return 0, newError(CodeRegisterIndex, "ReadRegister", fmt.Sprintf("register index %d out of range", i))
	}
	return t.regs[i], nil
}

// WriteRegister sets one register. Writes while running are rejected;
// validation occurs before any change.
func (t *Target) WriteRegister(i int, v uint32) error {
	const op = "WriteRegister"
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return newError(CodeTargetRunning, op, "cannot write register while running")
	}
	if i < 0 || i >= RegN {
		return newError(CodeRegisterIndex, op, fmt.Sprintf("register index %d out of range", i))
	}
	t.regs[i] = v
	return nil
}

// ReadRegisters returns a copy of all registers.
func (t *Target) ReadRegisters() ([RegN]uint32, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.regs, nil
}

// WriteRegisters sets all registers atomically. Rejected while running.
func (t *Target) WriteRegisters(regs [RegN]uint32) error {
	const op = "WriteRegisters"
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return newError(CodeTargetRunning, op, "cannot write registers while running")
	}
	t.regs = regs
	return nil
}

func (t *Target) sortedBreakpointsLocked() []Breakpoint {
	addrs := make([]uint32, 0, len(t.breakpoints))
	for a := range t.breakpoints {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })
	out := make([]Breakpoint, 0, len(addrs))
	for _, a := range addrs {
		bp := t.breakpoints[a]
		out = append(out, Breakpoint{Addr: bp.Addr, Hits: bp.Hits})
	}
	return out
}

// Breakpoints returns a sorted snapshot of all breakpoints.
func (t *Target) Breakpoints() []Breakpoint {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sortedBreakpointsLocked()
}

// SetBreakpoint installs a software breakpoint at an executable, aligned
// address. Repeat sets at the same address are idempotent and return the
// existing breakpoint with its accumulated hit count.
func (t *Target) SetBreakpoint(addr uint32) (*Breakpoint, error) {
	const op = "SetBreakpoint"
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return nil, newError(CodeTargetRunning, op, "cannot set breakpoint while running")
	}
	if bp, ok := t.breakpoints[addr]; ok {
		cp := *bp
		return &cp, nil // idempotent
	}
	if addr%InstSize != 0 {
		return nil, newError(CodeMisaligned, op,
			fmt.Sprintf("breakpoint address 0x%08x not aligned to %d bytes", addr, InstSize))
	}
	if err := t.checkRange(op, addr, int(InstSize), PermExec); err != nil {
		return nil, err
	}
	if len(t.breakpoints) >= t.opts.MaxBreakpoints {
		return nil, newError(CodeBreakpointLimit, op,
			fmt.Sprintf("breakpoint limit %d reached", t.opts.MaxBreakpoints))
	}
	bp := &Breakpoint{Addr: addr}
	t.breakpoints[addr] = bp
	cp := *bp
	return &cp, nil
}

// ClearBreakpoint removes a breakpoint. Clearing an address that has no
// breakpoint succeeds (idempotent).
func (t *Target) ClearBreakpoint(addr uint32) error {
	const op = "ClearBreakpoint"
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return newError(CodeTargetRunning, op, "cannot clear breakpoint while running")
	}
	delete(t.breakpoints, addr)
	return nil
}

func (t *Target) haltedLocked() bool {
	return t.stop.Kind == StopHalt || t.stop.Kind == StopFault
}

// Step executes exactly one instruction. Breakpoints are reported when the
// step lands on one; the breakpoint under the starting PC is transparent
// once (step-over), matching debugger single-step semantics.
func (t *Target) Step() (StopReason, error) {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return StopReason{}, newError(CodeTargetRunning, "Step", "target is already running")
	}
	if t.haltedLocked() {
		r := t.stop
		t.mu.Unlock()
		if r.Detail != nil {
			return r, r.Detail
		}
		return r, newError(CodeTargetHalted, "Step", "target is halted: "+r.Kind.String())
	}
	t.beginRunLocked()
	// Step executes the instruction at the current PC without the resume
	// pre-check, so stepping off a stopped breakpoint is transparent;
	// landing on a breakpoint afterwards reports normally.
	reason := t.execOneLocked()
	t.finishRunLocked(reason)
	t.mu.Unlock()
	return reason, reasonErr(reason)
}

// Resume starts asynchronous execution. The target runs until a
// breakpoint, halt, fault, interrupt or step-budget exhaustion. Wait for
// completion with WaitStopped.
func (t *Target) Resume() error {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return newError(CodeTargetRunning, "Resume", "target is already running")
	}
	if t.haltedLocked() {
		r := t.stop
		t.mu.Unlock()
		if r.Detail != nil {
			return r.Detail
		}
		return newError(CodeTargetHalted, "Resume", "target is halted: "+r.Kind.String())
	}
	// A breakpoint under the current PC stops a continue immediately.
	// Re-continuing from a stopped breakpoint is the debugger's explicit
	// choice: standard RSP requires it to stop again; to pass the site
	// the debugger must single-step or clear the breakpoint first.
	if bp, ok := t.breakpoints[t.regs[RegPC]]; ok {
		bp.Hits++
		r := StopReason{Kind: StopBreakpoint, PC: t.regs[RegPC], Hits: bp.Hits}
		t.stop = r
		t.mu.Unlock()
		return nil
	}
	// Publish running state synchronously and install fresh signalling.
	t.beginRunLocked()
	started := make(chan struct{})
	t.started = started
	t.mu.Unlock()

	go t.runLoop(started)
	// Return only after the run loop has first observed the running
	// state under the lock; then Resume()=>IsRunning()==true without
	// relying on scheduling or sleeps.
	<-started
	return nil
}

// runLoop executes instructions until a stop condition. The running flag
// is published before the goroutine starts. The lock is dropped between
// instructions so a parked Interrupt or mutator is handed the lock
// deterministically (Go mutex hand-off); no sleeps are involved.
func (t *Target) runLoop(started chan struct{}) {
	var budget uint64
	for {
		t.mu.Lock()
		if started != nil {
			close(started)
			started = nil
		}
		if t.interruptRequestedLocked() {
			t.finishRunLocked(StopReason{Kind: StopInterrupt, PC: t.regs[RegPC]})
			t.mu.Unlock()
			return
		}
		if t.opts.StepBudget > 0 && budget >= t.opts.StepBudget {
			t.finishRunLocked(StopReason{
				Kind:   StopFault,
				PC:     t.regs[RegPC],
				Detail: newError(CodeStepBudget, "Resume", "step budget exhausted"),
			})
			t.mu.Unlock()
			return
		}
		budget++
		reason := t.execOneLocked()
		if reason.Kind != StopNone {
			t.finishRunLocked(reason)
			t.mu.Unlock()
			return
		}
		// Publish state and hand the lock to any parked waiter.
		t.mu.Unlock()
	}
}

// beginRunLocked marks the target running with fresh signalling.
func (t *Target) beginRunLocked() {
	t.running = true
	t.stop = StopReason{}
	t.stopReq = make(chan struct{})
	t.doneCh = make(chan struct{})
}

// finishRunLocked records the terminal reason and signals completion.
func (t *Target) finishRunLocked(r StopReason) {
	t.running = false
	t.stop = r
	close(t.doneCh)
}

func (t *Target) interruptRequestedLocked() bool {
	select {
	case <-t.stopReq:
		return true
	default:
		return false
	}
}

// Interrupt requests an asynchronous stop of a running target. It is
// idempotent and deterministic: on return the target has converged to a
// stopped state (StopInterrupt unless an instruction-level stop raced and
// won). Interrupting a stopped target returns its current reason.
func (t *Target) Interrupt() error {
	t.mu.Lock()
	if !t.running {
		t.mu.Unlock()
		return nil
	}
	close(t.stopReq)
	done := t.doneCh
	t.mu.Unlock()
	<-done
	return nil
}

// WaitStopped blocks until the target is stopped and returns the reason.
func (t *Target) WaitStopped() StopReason {
	t.mu.Lock()
	done := t.doneCh
	running := t.running
	reason := t.stop
	t.mu.Unlock()
	if !running {
		return reason
	}
	<-done
	t.mu.Lock()
	reason = t.stop
	t.mu.Unlock()
	return reason
}

func intStopCode(k StopKind) Code {
	if k == StopFault {
		return CodeStepBudget // overridden by Detail at the call site where needed
	}
	return CodeTargetHalted
}

func reasonErr(r StopReason) error {
	if r.Detail != nil {
		return r.Detail
	}
	if r.Kind == StopHalt {
		return newError(CodeTargetHalted, "Step", "target halted")
	}
	return nil
}

// execOneLocked fetches and executes one instruction. Caller holds mu.
func (t *Target) execOneLocked() StopReason {
	pc := t.regs[RegPC]
	if err := t.checkRange("fetch", pc, int(InstSize), PermExec); err != nil {
		return StopReason{Kind: StopFault, PC: pc, Detail: err}
	}
	off := uint64(pc) - uint64(t.base)
	w := t.mem[off : off+uint64(InstSize)]
	op := Opcode(w[0])
	dst := w[1]
	s1, s0 := w[2], w[3]
	imm := uint16(w[2]) | uint16(w[3])<<8

	switch op {
	case OpNop:
		t.regs[RegPC] = pc + InstSize
	case OpHalt:
		return StopReason{Kind: StopHalt, PC: pc}
	case OpMovi:
		if dst >= RegN {
			return t.badReg(pc, "movi destination", dst)
		}
		t.regs[dst] = uint32(imm)
		t.regs[RegPC] = pc + InstSize
	case OpAdd, OpSub:
		if dst >= RegN || s1 >= RegN || s0 >= RegN {
			return t.badReg(pc, "arithmetic operand", dst)
		}
		if op == OpAdd {
			t.regs[dst] = t.regs[s1] + t.regs[s0]
		} else {
			t.regs[dst] = t.regs[s1] - t.regs[s0]
		}
		t.regs[RegPC] = pc + InstSize
	case OpLd:
		if dst >= RegN {
			return t.badReg(pc, "load destination", dst)
		}
		addr := uint32(imm)
		if err := t.checkRange("load", addr, 4, PermRead); err != nil {
			return StopReason{Kind: StopFault, PC: pc, Detail: err}
		}
		if addr%InstSize != 0 {
			return StopReason{Kind: StopFault, PC: pc,
				Detail: newError(CodeMisaligned, "load", fmt.Sprintf("unaligned load 0x%08x", addr))}
		}
		oo := uint64(addr) - uint64(t.base)
		t.regs[dst] = uint32(t.mem[oo]) | uint32(t.mem[oo+1])<<8 |
			uint32(t.mem[oo+2])<<16 | uint32(t.mem[oo+3])<<24
		t.regs[RegPC] = pc + InstSize
	case OpSt:
		src := w[1]
		if src >= RegN {
			return t.badReg(pc, "store source", src)
		}
		addr := uint32(imm)
		if addr%InstSize != 0 {
			return StopReason{Kind: StopFault, PC: pc,
				Detail: newError(CodeMisaligned, "store", fmt.Sprintf("unaligned store 0x%08x", addr))}
		}
		if err := t.checkRange("store", addr, 4, PermWrite); err != nil {
			return StopReason{Kind: StopFault, PC: pc, Detail: err}
		}
		oo := uint64(addr) - uint64(t.base)
		v := t.regs[src]
		t.mem[oo] = byte(v)
		t.mem[oo+1] = byte(v >> 8)
		t.mem[oo+2] = byte(v >> 16)
		t.mem[oo+3] = byte(v >> 24)
		t.regs[RegPC] = pc + InstSize
	case OpJmp:
		return t.jumpLocked(pc, uint32(imm))
	case OpBz:
		reg := w[1]
		if reg >= RegN {
			return t.badReg(pc, "branch operand", reg)
		}
		if t.regs[reg] == 0 {
			return t.jumpLocked(pc, uint32(imm))
		}
		t.regs[RegPC] = pc + InstSize
	case OpJmpi:
		reg := w[1]
		if reg >= RegN {
			return t.badReg(pc, "indirect jump operand", reg)
		}
		return t.jumpLocked(pc, uint32(imm)+t.regs[reg])
	case OpIll:
		return StopReason{Kind: StopFault, PC: pc,
			Detail: newError(CodeNotExecutable, "execute", "illegal instruction")}
	default:
		return StopReason{Kind: StopFault, PC: pc,
			Detail: newError(CodeNotExecutable, "execute",
				fmt.Sprintf("undefined opcode 0x%02x at 0x%08x", byte(op), pc))}
	}

	// Post-instruction breakpoint landing (single-step and run loop).
	np := t.regs[RegPC]
	if bp, ok := t.breakpoints[np]; ok {
		bp.Hits++
		return StopReason{Kind: StopBreakpoint, PC: np, Hits: bp.Hits}
	}
	return StopReason{}
}

func (t *Target) jumpLocked(pc, target uint32) StopReason {
	if target%InstSize != 0 {
		return StopReason{Kind: StopFault, PC: pc,
			Detail: newError(CodeMisaligned, "jump", fmt.Sprintf("unaligned target 0x%08x", target))}
	}
	if err := t.checkRange("jump", target, int(InstSize), PermExec); err != nil {
		return StopReason{Kind: StopFault, PC: pc, Detail: err}
	}
	t.regs[RegPC] = target
	return StopReason{}
}

func (t *Target) badReg(pc uint32, what string, idx byte) StopReason {
	return StopReason{Kind: StopFault, PC: pc,
		Detail: newError(CodeRegisterIndex, "execute",
			fmt.Sprintf("%s register r%d out of range", what, idx))}
}
