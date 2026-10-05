package target

import (
	"context"
	"fmt"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/image"
)

// fetchLocked reads and decodes the instruction at pc. Caller holds t.mu.
func (t *Target) fetchLocked(pc uint32) (uint32, error) {
	if pc%4 != 0 {
		return 0, fmt.Errorf("%w: pc %#x", ErrAlignment, pc)
	}
	rg, err := t.findRegionLocked(pc, 4)
	if err != nil {
		return 0, err
	}
	if !rg.Perm.Has(image.PermExecute) {
		return 0, fmt.Errorf("%w: execute in non-executable %q @%#x", ErrBadPerm, rg.Name, pc)
	}
	off := int(pc - rg.Addr)
	word := uint32(rg.Data[off]) | uint32(rg.Data[off+1])<<8 |
		uint32(rg.Data[off+2])<<16 | uint32(rg.Data[off+3])<<24
	if op := word >> 24; op > OpBRK {
		return 0, fmt.Errorf("%w: illegal opcode %#02x @%#x", ErrIllegalInstr, op, pc)
	}
	return word, nil
}

// qualifiesLocked reports whether a hit on this breakpoint should stop
// execution: the cumulative hit count must have reached the threshold (if
// any) and the condition (if any) must hold. Caller holds t.mu.
func (bp *breakpoint) qualifiesLocked(t *Target) bool {
	if bp.threshold > 0 && bp.hits < bp.threshold {
		return false
	}
	if bp.cond != nil && !bp.cond.evalLocked(t) {
		return false
	}
	return true
}

// decode fields of an instruction word.
func decode(w uint32) (op, rd, rs uint8, imm uint16) {
	return uint8(w >> 24), uint8(w>>20) & 0xF, uint8(w>>16) & 0xF, uint16(w)
}

// Encode builds an instruction word (helper for tests and the demo builder).
func Encode(op, rd, rs uint8, imm uint16) uint32 {
	return uint32(op)<<24 | uint32(rd&0xF)<<20 | uint32(rs&0xF)<<16 | uint32(imm)
}

// stepLocked executes exactly one instruction. Caller holds t.mu. Returns the
// halt info when execution should stop, or zero halt info to keep running.
// On fault it records ReasonFault and returns; registers/memory prior to the
// faulting instruction remain valid and PC stays at the faulting instruction.
func (t *Target) stepLocked(overBreakpoint bool) HaltInfo {
	pc := t.regs[RegPC]

	// Dynamic (hardware) breakpoint at the instruction about to execute,
	// unless the debugger explicitly asked to step over it.
	if !overBreakpoint {
		if bp, ok := t.breakpts[pc]; ok && bp.enabled {
			bp.hits++
			if bp.qualifiesLocked(t) {
				bp.stops++
				reason := ReasonBreakpoint
				if bp.cond != nil || bp.threshold > 0 {
					reason = ReasonBreakpointCond
				}
				info := HaltInfo{Reason: reason, PC: pc, BPAddr: pc, BPHits: bp.hits}
				t.state = StateHalted
				t.lastHalt = info
				return info
			}
			// Condition false or threshold not yet reached: count the hit
			// (visible via Breakpoints) but keep executing.
		}
	}

	word, err := t.fetchLocked(pc)
	if err != nil {
		return t.faultLocked(pc, FaultAccess, err.Error())
	}
	op, rd, rs, imm := decode(word)

	// BRK is a static trap encoded in the image itself.
	if op == OpBRK {
		info := HaltInfo{Reason: ReasonBreakpoint, PC: pc, BPAddr: pc}
		t.state = StateHalted
		t.lastHalt = info
		return info
	}

	// Compute the architectural effect. Memory accesses are validated before
	// register commit, so a faulting instruction mutates nothing.
	nextPC := pc + 4
	switch op {
	case OpHALT:
		t.regs[RegPC] = pc // stop at HALT
		info := HaltInfo{Reason: ReasonTerminated, PC: pc}
		t.state = StateTerminated
		t.lastHalt = info
		return info

	case OpMOVI:
		t.regs[rd] = uint32(imm)

	case OpMOVR:
		if rd != RegZero {
			t.regs[rd] = t.regs[rs]
		}

	case OpADD:
		if rd != RegZero {
			t.regs[rd] = t.regs[rd] + t.regs[rs]
		}

	case OpADDI:
		if rd != RegZero {
			t.regs[rd] = t.regs[rd] + uint32(imm)
		}

	case OpLOAD:
		addr := uint32(imm)
		rg, err := t.findRegionLocked(addr, 4)
		if err != nil {
			return t.faultLocked(pc, FaultAccess, err.Error())
		}
		if !rg.Perm.Has(image.PermRead) {
			return t.faultLocked(pc, FaultAccess,
				fmt.Sprintf("LOAD @%#x: region %q not readable", addr, rg.Name))
		}
		if addr%4 != 0 {
			return t.faultLocked(pc, FaultUnaligned,
				fmt.Sprintf("LOAD @%#x unaligned", addr))
		}
		off := int(addr - rg.Addr)
		v := uint32(rg.Data[off]) | uint32(rg.Data[off+1])<<8 |
			uint32(rg.Data[off+2])<<16 | uint32(rg.Data[off+3])<<24
		if rd != RegZero {
			t.regs[rd] = v
		}

	case OpSTORE:
		addr := uint32(imm)
		if addr%4 != 0 {
			return t.faultLocked(pc, FaultUnaligned,
				fmt.Sprintf("STORE @%#x unaligned", addr))
		}
		rg, err := t.findRegionLocked(addr, 4)
		if err != nil {
			return t.faultLocked(pc, FaultAccess, err.Error())
		}
		if !rg.Perm.Has(image.PermWrite) {
			return t.faultLocked(pc, FaultAccess,
				fmt.Sprintf("STORE @%#x: region %q is read-only", addr, rg.Name))
		}
		off := int(addr - rg.Addr)
		v := t.regs[rs]
		rg.Data[off] = byte(v)
		rg.Data[off+1] = byte(v >> 8)
		rg.Data[off+2] = byte(v >> 16)
		rg.Data[off+3] = byte(v >> 24)

	case OpJMP:
		target := uint32(imm)
		if _, err := t.fetchLocked(target); err != nil {
			return t.faultLocked(pc, FaultAccess, err.Error())
		}
		nextPC = target

	case OpJZ:
		if t.regs[rd] == 0 {
			target := uint32(imm)
			if _, err := t.fetchLocked(target); err != nil {
				return t.faultLocked(pc, FaultAccess, err.Error())
			}
			nextPC = target
		}

	default:
		// fetchLocked already bounds the opcode; a bad decode reaches here only
		// for an opcode without an implementation.
		return t.faultLocked(pc, FaultDecode, fmt.Sprintf("opcode %#02x", op))
	}

	t.regs[RegPC] = nextPC
	t.regs[RegZero] = 0
	return HaltInfo{}
}

func (t *Target) faultLocked(pc uint32, code FaultCode, msg string) HaltInfo {
	info := HaltInfo{Reason: ReasonFault, PC: pc, Fault: code, FaultMsg: msg}
	t.state = StateHalted
	t.lastHalt = info
	return info
}

// Step executes exactly one instruction. A breakpoint installed at the current
// PC is stepped over once (its hit count is not incremented by the step
// itself); this mirrors hardware single-step semantics.
func (t *Target) Step() (HaltInfo, error) {
	t.mu.Lock()
	if err := t.requireHaltedLocked(); err != nil {
		t.mu.Unlock()
		return HaltInfo{}, err
	}
	t.state = StateRunning
	_, over := t.breakpts[t.regs[RegPC]]
	if over && !t.breakpts[t.regs[RegPC]].enabled {
		over = false
	}
	info := t.stepLocked(over)
	if info.Reason == ReasonNone {
		info = HaltInfo{Reason: ReasonStep, PC: t.regs[RegPC]}
		t.state = StateHalted
		t.lastHalt = info
	}
	t.mu.Unlock()
	return info, nil
}

// Continue runs until a breakpoint, HALT, fault or interrupt. It is
// synchronous: the goroutine blocks here, and Interrupt (or canceling ctx)
// stops it. Determinism in tests comes from direct calls and channels, never
// from wall-clock sleeps.
func (t *Target) Continue() (HaltInfo, error) {
	return t.ContinueCtx(context.Background())
}

// ContinueCtx is Continue with an interruptible context. Cancellation behaves
// exactly like Interrupt: the current instruction completes, state becomes
// halted with ReasonPause and PC at the next instruction boundary.
func (t *Target) ContinueCtx(ctx context.Context) (HaltInfo, error) {
	return t.continueCtx(ctx, nil)
}

// ContinueStarted is ContinueCtx plus a start signal: started (if non-nil) is
// closed once the core is marked running and the run handle is registered,
// so a caller that needs to Interrupt afterwards cannot race the startup.
func (t *Target) ContinueStarted(ctx context.Context, started chan<- struct{}) (HaltInfo, error) {
	return t.continueCtx(ctx, started)
}

func (t *Target) continueCtx(ctx context.Context, started chan<- struct{}) (HaltInfo, error) {
	t.mu.Lock()
	if err := t.requireHaltedLocked(); err != nil {
		t.mu.Unlock()
		return HaltInfo{}, err
	}
	t.state = StateRunning
	run := &runHandle{stop: make(chan struct{}), done: make(chan struct{})}
	t.run = run
	t.mu.Unlock()
	if started != nil {
		close(started)
	}
	defer close(run.done)

	ctxStop := make(chan struct{})
	defer close(ctxStop)
	go func() {
		select {
		case <-ctx.Done():
			run.cancel()
		case <-ctxStop:
		}
	}()

	pause := func() HaltInfo {
		t.mu.Lock()
		defer t.mu.Unlock()
		if t.state == StateRunning {
			t.state = StateHalted
			t.lastHalt = HaltInfo{Reason: ReasonPause, PC: t.regs[RegPC]}
		}
		if t.run == run {
			t.run = nil
		}
		return t.lastHalt
	}

	// When resuming after a dynamic-breakpoint trap, the instruction at the
	// trap PC is single-stepped once so execution can leave before breakpoint
	// checks resume (hardware resume semantics). An initial halt at a breakpoint
	// address (or a step/PAUSE) still traps on the first hit.
	skipFirst := false
	t.mu.Lock()
	if t.lastHalt.Reason == ReasonBreakpoint || t.lastHalt.Reason == ReasonBreakpointCond {
		if bp, ok := t.breakpts[t.regs[RegPC]]; ok && bp.enabled {
			skipFirst = true
		}
	}
	t.mu.Unlock()

	t.mu.Lock()
	budget := t.budget
	t.mu.Unlock()
	for i := uint64(0); budget == 0 || i < budget; i++ {
		select {
		case <-run.stop:
			return pause(), nil
		default:
		}
		t.mu.Lock()
		if t.state != StateRunning {
			info := t.lastHalt
			if t.run == run {
				t.run = nil
			}
			t.mu.Unlock()
			return info, nil
		}
		over := skipFirst
		skipFirst = false
		info := t.stepLocked(over)
		if info.Reason != ReasonNone {
			if t.run == run {
				t.run = nil
			}
			t.mu.Unlock()
			return info, nil
		}
		t.mu.Unlock()
	}

	t.mu.Lock()
	if t.run == run {
		t.run = nil
	}
	info := t.faultLocked(t.regs[RegPC], FaultDecode, "instruction budget exhausted (runaway loop)")
	t.mu.Unlock()
	return info, nil
}

// Interrupt requests an asynchronous stop of a running target and blocks until
// the execution loop has actually halted at an instruction boundary. Safe to
// call concurrently; repeated interrupts are idempotent and return the same
// halt info.
func (t *Target) Interrupt() (HaltInfo, error) {
	t.mu.Lock()
	run := t.run
	state := t.state
	t.mu.Unlock()

	switch state {
	case StateTerminated:
		return t.HaltInfo(), ErrTerminated
	case StateHalted:
		if run == nil {
			return t.HaltInfo(), nil
		}
	}
	run.cancel()
	<-run.done
	return t.HaltInfo(), nil
}
