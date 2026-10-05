package session

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/image"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

// Error codes used in Exx replies.
const (
	ErrGeneric          byte = 0x01
	ErrProtoCaps        byte = 0x02
	ErrProtoFirstPacket byte = 0x03
	ErrRunning          byte = 0x10
	ErrTerminated       byte = 0x11
	ErrBadRegister      byte = 0x20
	ErrReadOnly         byte = 0x21
	ErrAlignment        byte = 0x22
	ErrOutOfRange       byte = 0x23
	ErrBadPerm          byte = 0x24
	ErrBPLimit          byte = 0x30
	ErrBPConflict       byte = 0x31
	ErrNoBP             byte = 0x32
	ErrBPBadAddr        byte = 0x33
	ErrBPBadCond        byte = 0x34
	ErrSymbol           byte = 0x40
	ErrUnknownCmd       byte = 0xFF
)

// errorReply formats a two-digit hex error.
func errorReply(code byte) string {
	return fmt.Sprintf("E%02x", code)
}

// mapTargetError translates a target error into an Exx code.
func mapTargetError(err error) byte {
	switch {
	case errors.Is(err, target.ErrRunning):
		return ErrRunning
	case errors.Is(err, target.ErrTerminated):
		return ErrTerminated
	case errors.Is(err, target.ErrInvalidRegister):
		return ErrBadRegister
	case errors.Is(err, target.ErrReadOnlyReg):
		return ErrReadOnly
	case errors.Is(err, target.ErrAlignment):
		return ErrAlignment
	case errors.Is(err, target.ErrOutOfRange):
		return ErrOutOfRange
	case errors.Is(err, target.ErrBadPerm):
		return ErrBadPerm
	case errors.Is(err, target.ErrBPLimit):
		return ErrBPLimit
	case errors.Is(err, target.ErrBPConflict):
		return ErrBPConflict
	case errors.Is(err, target.ErrNoBreakpoint):
		return ErrNoBP
	case errors.Is(err, target.ErrBPBadAddr):
		return ErrBPBadAddr
	case errors.Is(err, target.ErrBPBadCond):
		return ErrBPBadCond
	case errors.Is(err, image.ErrSymbolNotFound):
		return ErrSymbol
	default:
		return ErrGeneric
	}
}

// stopReply encodes the current halt reason ("Sxx").
func stopReply(t *target.Target) string {
	info := t.HaltInfo()
	var sig byte
	switch info.Reason {
	case target.ReasonBreakpoint:
		sig = 0x05 // SIGTRAP
	case target.ReasonTerminated:
		sig = 0x00
	case target.ReasonFault:
		sig = 0x0B // SIGSEGV-ish
	default:
		sig = 0x05
	}
	return fmt.Sprintf("S%02x", sig)
}

// dispatch executes one request and returns the raw reply plus a detach flag.
func (sess *Session) dispatch(req []byte) (string, bool) {
	s := string(req)
	sess.log.Printf("frame <- %q", s)

	switch {
	case s == "?":
		return stopReply(sess.target), false
	case s == "g":
		return sess.readAllRegs(), false
	case strings.HasPrefix(s, "p"):
		return sess.readOneReg(s[1:]), false
	case strings.HasPrefix(s, "P"):
		return sess.writeReg(s[1:]), false
	case strings.HasPrefix(s, "m"):
		return sess.readMem(s[1:]), false
	case strings.HasPrefix(s, "X"):
		return sess.writeMemBinary(s[1:], req), false
	case strings.HasPrefix(s, "M"):
		return sess.writeMemHex(s[1:]), false
	case strings.HasPrefix(s, "Z0,") || strings.HasPrefix(s, "Z1,"):
		return sess.setBP(s), false
	case strings.HasPrefix(s, "z0,") || strings.HasPrefix(s, "z1,"):
		return sess.clearBP(s), false
	case s == "s":
		return sess.step(), false
	case s == "c":
		// Begin asynchronous execution. The terminal stop reply is sent by
		// the session loop when the run halts; no immediate frame goes out.
		sess.startRun()
		return noReply, false
	case s == "\x03" || s == "vCtrlC":
		sess.interruptTarget()
		return stopReply(sess.target), false
	case s == "qC":
		return "QC1", false
	case s == "qAttached":
		sess.attached = true
		return "1", false
	case strings.HasPrefix(s, "qSymbol:"):
		return sess.lookupSymbol(s), false
	case s == "qXfer:memory-map:read" || strings.HasPrefix(s, "qXfer:memory-map:read:"):
		return sess.memoryMap(), false
	case s == "qSupported":
		return "", false // negotiation already completed; ignore duplicate
	case s == "D" || s == "k" || s == "vKill":
		return "OK", true
	case strings.HasPrefix(s, "qRcmd,"):
		return sess.rcmd(s), false
	case s == "qBPList":
		return sess.bpList(), false
	case strings.HasPrefix(s, "qBPEnable,"):
		return sess.bpEnable(s[len("qBPEnable,"):], true), false
	case strings.HasPrefix(s, "qBPDisable,"):
		return sess.bpEnable(s[len("qBPDisable,"):], false), false
	case strings.HasPrefix(s, "qBPBatch,"):
		return sess.bpBatch(s[len("qBPBatch,"):]), false
	case s == "qStopInfo":
		return sess.stopInfo(), false
	case strings.HasPrefix(s, "q") || strings.HasPrefix(s, "v"):
		// Unsupported query: empty reply means "not supported".
		return "", false
	default:
		sess.log.Printf("reject: unknown command %q", s)
		return errorReply(ErrUnknownCmd), false
	}
}

func (sess *Session) readAllRegs() string {
	regs, err := sess.target.Regs()
	if err != nil {
		return errorReply(mapTargetError(err))
	}
	var sb strings.Builder
	for _, r := range regs {
		sb.WriteString(fmt.Sprintf("%08x", r))
	}
	return sb.String()
}

func parseRegNum(s string) (int, bool) {
	// Register numbers on the wire are hexadecimal ("pf" == register 15).
	n, err := strconv.ParseInt(s, 16, 32)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

func (sess *Session) readOneReg(arg string) string {
	n, ok := parseRegNum(arg)
	if !ok {
		return errorReply(ErrBadRegister)
	}
	v, err := sess.target.ReadReg(n)
	if err != nil {
		return errorReply(mapTargetError(err))
	}
	return fmt.Sprintf("%08x", v)
}

func (sess *Session) writeReg(arg string) string {
	i := strings.IndexByte(arg, '=')
	if i < 0 {
		return errorReply(ErrBadRegister)
	}
	n, ok := parseRegNum(arg[:i])
	if !ok {
		return errorReply(ErrBadRegister)
	}
	v, err := strconv.ParseUint(arg[i+1:], 16, 32)
	if err != nil {
		return errorReply(ErrBadRegister)
	}
	if err := sess.target.WriteReg(n, uint32(v)); err != nil {
		return errorReply(mapTargetError(err))
	}
	return "OK"
}

// parseAddrLen splits "addr,len" (both hex).
func parseAddrLen(arg string) (uint32, int, error) {
	parts := strings.SplitN(arg, ",", 2)
	if len(parts) != 2 {
		return 0, 0, errors.New("bad addr,len")
	}
	a, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return 0, 0, err
	}
	n, err := strconv.ParseInt(parts[1], 16, 64)
	if err != nil || n <= 0 {
		return 0, 0, errors.New("bad length")
	}
	return uint32(a), int(n), nil
}

func (sess *Session) readMem(arg string) string {
	addr, n, err := parseAddrLen(arg)
	if err != nil {
		return errorReply(ErrAlignment)
	}
	data, err := sess.target.ReadMem(addr, n)
	if err != nil {
		return errorReply(mapTargetError(err))
	}
	return hex.EncodeToString(data)
}

func (sess *Session) writeMemHex(arg string) string {
	parts := strings.SplitN(arg, ":", 2)
	if len(parts) != 2 {
		return errorReply(ErrAlignment)
	}
	addr, n, err := parseAddrLen(parts[0])
	if err != nil {
		return errorReply(ErrAlignment)
	}
	data, err := hex.DecodeString(parts[1])
	if err != nil || len(data) != n {
		return errorReply(ErrAlignment)
	}
	if err := sess.target.WriteMem(addr, data); err != nil {
		return errorReply(mapTargetError(err))
	}
	return "OK"
}

// writeMemBinary handles "Xaddr,len:binary". The body is raw bytes.
func (sess *Session) writeMemBinary(arg string, raw []byte) string {
	s := string(arg)
	colon := strings.IndexByte(s, ':')
	if colon < 0 {
		return errorReply(ErrAlignment)
	}
	addr, n, err := parseAddrLen(s[:colon])
	if err != nil {
		return errorReply(ErrAlignment)
	}
	// raw is the full original request; binary payload begins after
	// "X<colon-part>:".
	prefixLen := 1 + colon + 1
	payload := raw[prefixLen:]
	if len(payload) != n {
		return errorReply(ErrAlignment)
	}
	if err := sess.target.WriteMem(addr, payload); err != nil {
		return errorReply(mapTargetError(err))
	}
	return "OK"
}

// parseZArg splits "type,addr,kind[;th=<hex>][;cond=<hex-text>]". The
// optional suffixes attach a hit-count threshold and a condition expression
// (hex-encoded source text) to a hardware breakpoint.
func parseZArg(s string) (target.BreakpointSpec, error) {
	var spec target.BreakpointSpec
	main, opts, _ := strings.Cut(s, ";")
	parts := strings.SplitN(main, ",", 3)
	if len(parts) != 3 {
		return spec, errors.New("bad breakpoint spec")
	}
	a, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil {
		return spec, err
	}
	spec.Addr = uint32(a)
	for _, opt := range strings.Split(opts, ";") {
		if opt == "" {
			continue
		}
		k, v, ok := strings.Cut(opt, "=")
		if !ok {
			return spec, errors.New("bad breakpoint option")
		}
		switch k {
		case "th":
			th, err := strconv.ParseUint(v, 16, 64)
			if err != nil {
				return spec, err
			}
			spec.Threshold = th
		case "cond":
			raw, err := hex.DecodeString(v)
			if err != nil {
				return spec, err
			}
			spec.Condition = string(raw)
		default:
			return spec, errors.New("unknown breakpoint option")
		}
	}
	return spec, nil
}

func (sess *Session) setBP(s string) string {
	spec, err := parseZArg(s)
	if err != nil {
		return errorReply(ErrBPBadAddr)
	}
	if err := sess.target.SetBreakpointSpec(spec); err != nil {
		return errorReply(mapTargetError(err))
	}
	sess.log.Printf("bp set %#x th=%d cond=%q (slots=%d)", spec.Addr,
		effectiveThreshold(spec.Threshold), spec.Condition, len(sess.target.Breakpoints()))
	return "OK"
}

// effectiveThreshold mirrors the target's 0-means-1 rule for log output.
func effectiveThreshold(th uint64) uint64 {
	if th == 0 {
		return 1
	}
	return th
}

func (sess *Session) clearBP(s string) string {
	spec, err := parseZArg(s)
	if err != nil {
		return errorReply(ErrBPBadAddr)
	}
	if err := sess.target.ClearBreakpoint(spec.Addr); err != nil {
		return errorReply(mapTargetError(err))
	}
	sess.log.Printf("bp clear %#x (slots=%d)", spec.Addr, len(sess.target.Breakpoints()))
	return "OK"
}

// bpList answers "qBPList" with one entry per breakpoint:
// "<addr>,<enabled>,<hits>,<skips>,<threshold>,<condhex>" joined by ";",
// or "none" when the table is empty. All numbers are hex except the
// enabled flag (0/1).
func (sess *Session) bpList() string {
	bps := sess.target.Breakpoints()
	if len(bps) == 0 {
		return "none"
	}
	var sb strings.Builder
	for i, b := range bps {
		if i > 0 {
			sb.WriteByte(';')
		}
		en := 0
		if b.Enabled {
			en = 1
		}
		fmt.Fprintf(&sb, "%x,%d,%x,%x,%x,%s", b.Addr, en, b.Hits, b.Skips,
			effectiveThreshold(b.Threshold), hex.EncodeToString([]byte(b.Condition)))
	}
	return sb.String()
}

// bpEnable handles "qBPEnable,<addr>" / "qBPDisable,<addr>" (hex addr).
func (sess *Session) bpEnable(arg string, enabled bool) string {
	a, err := strconv.ParseUint(arg, 16, 32)
	if err != nil {
		return errorReply(ErrBPBadAddr)
	}
	if err := sess.target.EnableBreakpoint(uint32(a), enabled); err != nil {
		return errorReply(mapTargetError(err))
	}
	sess.log.Printf("bp %#x enabled=%v", a, enabled)
	return "OK"
}

// bpBatch handles "qBPBatch,<spec>;<spec>..." where each spec is
// "<addrhex>:<thhex>:<condhex>" (condhex empty for none). The whole batch
// is validated before commit: one bad item rejects everything and leaves
// the breakpoint table untouched.
func (sess *Session) bpBatch(arg string) string {
	if arg == "" {
		return errorReply(ErrBPBadAddr)
	}
	var specs []target.BreakpointSpec
	for _, item := range strings.Split(arg, ";") {
		parts := strings.SplitN(item, ":", 3)
		if len(parts) != 3 {
			return errorReply(ErrBPBadAddr)
		}
		a, err := strconv.ParseUint(parts[0], 16, 32)
		if err != nil {
			return errorReply(ErrBPBadAddr)
		}
		th, err := strconv.ParseUint(parts[1], 16, 64)
		if err != nil {
			return errorReply(ErrBPBadAddr)
		}
		var cond string
		if parts[2] != "" {
			raw, err := hex.DecodeString(parts[2])
			if err != nil {
				return errorReply(ErrBPBadAddr)
			}
			cond = string(raw)
		}
		specs = append(specs, target.BreakpointSpec{
			Addr: uint32(a), Threshold: th, Condition: cond,
		})
	}
	if err := sess.target.SetBreakpointsBatch(specs); err != nil {
		code := mapTargetError(err)
		sess.log.Printf("reject: bp batch of %d -> %s", len(specs), errorReply(code))
		return errorReply(code)
	}
	sess.log.Printf("bp batch committed %d specs (slots=%d)", len(specs), len(sess.target.Breakpoints()))
	return "OK"
}

// stopInfo answers "qStopInfo" with a detailed stop report:
// "reason=<name>" plus, for breakpoint stops, the address and the
// hit/skip counters of that breakpoint. Clients use this to tell a real
// breakpoint stop apart from an external interrupt (pause) and to see how
// many hits were skipped because the condition or threshold was not met.
func (sess *Session) stopInfo() string {
	info := sess.target.HaltInfo()
	var sb strings.Builder
	fmt.Fprintf(&sb, "reason=%s", info.Reason)
	switch info.Reason {
	case target.ReasonBreakpoint:
		fmt.Fprintf(&sb, ";addr=%x", info.BPAddr)
		for _, b := range sess.target.Breakpoints() {
			if b.Addr == info.BPAddr {
				fmt.Fprintf(&sb, ";hits=%x;skips=%x", b.Hits, b.Skips)
				break
			}
		}
	case target.ReasonFault:
		fmt.Fprintf(&sb, ";fault=%s", info.Fault)
	}
	fmt.Fprintf(&sb, ";pc=%x", info.PC)
	return sb.String()
}

func (sess *Session) step() string {
	info, err := sess.target.Step()
	if err != nil {
		return errorReply(mapTargetError(err))
	}
	sess.log.Printf("state -> halted(step) pc=%#x", info.PC)
	return stopReply(sess.target)
}

// lookupSymbol handles "qSymbol:<hex-name>". Returns the address as a synthetic
// "qSymbol:<hex-name>:<hex-addr>" style answer when found, else Exx.
func (sess *Session) lookupSymbol(s string) string {
	payload := strings.TrimPrefix(s, "qSymbol:")
	if payload == "" {
		// Client announcing symbol readiness: acknowledge.
		return "OK"
	}
	raw, err := hex.DecodeString(payload)
	if err != nil {
		return errorReply(ErrSymbol)
	}
	addr, err := sess.target.LookupSymbol(string(raw))
	if err != nil {
		code := mapTargetError(err)
		sess.log.Printf("reject: symbol %q missing -> %s", string(raw), errorReply(code))
		return errorReply(code)
	}
	return fmt.Sprintf("%s:%08x", payload, addr)
}

func (sess *Session) memoryMap() string {
	if !sess.caps.memMap {
		return "" // negotiated degradation: feature absent
	}
	var sb strings.Builder
	sb.WriteString("l<?xml version=\"1.0\"?>")
	sb.WriteString("<memory-map>")
	for _, seg := range sess.target.MemoryMap() {
		sb.WriteString(fmt.Sprintf(
			"<memory type=%q start=\"%#x\" length=\"%#x\"/>",
			regionType(seg.Perm), seg.Addr, seg.Size))
	}
	sb.WriteString("</memory-map>")
	return sb.String()
}

func regionType(p image.Perm) string {
	if p.Has(image.PermExecute) {
		return "rom"
	}
	return "ram"
}

// rcmd executes "qRcmd,<hex-command>". Supported: reset.
func (sess *Session) rcmd(s string) string {
	if !sess.caps.qRcmd {
		return ""
	}
	payload := strings.TrimPrefix(s, "qRcmd,")
	cmd, err := hex.DecodeString(payload)
	if err != nil {
		return errorReply(ErrGeneric)
	}
	switch string(cmd) {
	case "reset":
		if err := sess.target.Reset(); err != nil {
			return errorReply(mapTargetError(err))
		}
		return "OK"
	default:
		return errorReply(ErrUnknownCmd)
	}
}
