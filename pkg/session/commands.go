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

// stopReply encodes the current halt reason. The base "Sxx" keeps gdb signal
// semantics; a ";key:value" extension suffix lets clients distinguish plain
// breakpoint hits, conditional/threshold stops, interrupts and faults without
// a round trip. Replies always start with "S" for backward compatibility.
func stopReply(t *target.Target) string {
	info := t.HaltInfo()
	switch info.Reason {
	case target.ReasonBreakpoint:
		// Dynamic slot at the trap address => plain hardware breakpoint;
		// otherwise it is a static BRK instruction in the image.
		if _, ok := findBP(t, info.BPAddr); ok {
			return fmt.Sprintf("S05;reason:bp;addr:%x;hits:%d", info.BPAddr, info.BPHits)
		}
		return fmt.Sprintf("S05;reason:brk;addr:%x", info.BPAddr)
	case target.ReasonBreakpointCond:
		return fmt.Sprintf("S05;reason:condbp;addr:%x;hits:%d", info.BPAddr, info.BPHits)
	case target.ReasonStep:
		return "S05;reason:step"
	case target.ReasonPause:
		return "S02;reason:pause"
	case target.ReasonTerminated:
		return "S00;reason:exit"
	case target.ReasonFault:
		return fmt.Sprintf("S0b;reason:fault;code:%s", info.Fault)
	default:
		return "S05"
	}
}

// findBP locates one installed breakpoint by address.
func findBP(t *target.Target, addr uint32) (target.BreakpointInfo, bool) {
	for _, b := range t.Breakpoints() {
		if b.Addr == addr {
			return b, true
		}
	}
	return target.BreakpointInfo{}, false
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
	case s == "qBp":
		return sess.bpStatus(), false
	case strings.HasPrefix(s, "qBpEn,"):
		return sess.bpEnable(s[len("qBpEn,"):], true), false
	case strings.HasPrefix(s, "qBpDis,"):
		return sess.bpEnable(s[len("qBpDis,"):], false), false
	case strings.HasPrefix(s, "qBpCfg,"):
		return sess.bpConfigure(s[len("qBpCfg,"):]), false
	case strings.HasPrefix(s, "qBpBatch,"):
		return sess.bpBatch(s[len("qBpBatch,"):]), false
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

// parseZArg splits "type,addr,kind[;th=<n>][;cond=<hex>]". The optional
// extensions attach a hit-count threshold and a hex-encoded condition
// expression to a Z1 set.
func parseZArg(s string) (uint32, error) {
	parts := strings.SplitN(s, ",", 3)
	if len(parts) != 3 {
		return 0, errors.New("bad breakpoint spec")
	}
	a, err := strconv.ParseUint(parts[1], 16, 32)
	return uint32(a), err
}

// parseBPExt parses ";th=<n>;cond=<hex>" suffixes from a Z1 kind field.
func parseBPExt(kindField string) (threshold uint64, cond string, err error) {
	for _, ext := range strings.Split(kindField, ";")[1:] {
		kv := strings.SplitN(ext, "=", 2)
		if len(kv) != 2 {
			return 0, "", errors.New("bad breakpoint extension")
		}
		switch kv[0] {
		case "th":
			threshold, err = strconv.ParseUint(kv[1], 10, 64)
			if err != nil {
				return 0, "", errors.New("bad threshold")
			}
		case "cond":
			raw, derr := hex.DecodeString(kv[1])
			if derr != nil {
				return 0, "", errors.New("bad condition encoding")
			}
			cond = string(raw)
		default:
			return 0, "", errors.New("unknown breakpoint extension")
		}
	}
	return threshold, cond, nil
}

func (sess *Session) setBP(s string) string {
	addr, err := parseZArg(s)
	if err != nil {
		return errorReply(ErrBPBadAddr)
	}
	kindField := strings.SplitN(s, ",", 3)[2]
	threshold, cond, err := parseBPExt(kindField)
	if err != nil {
		sess.log.Printf("reject: bp extension %q: %v", kindField, err)
		return errorReply(ErrBPBadAddr)
	}
	spec := target.BreakpointSpec{Addr: addr, Cond: cond, Threshold: threshold}
	if err := sess.target.SetBreakpointEx(spec); err != nil {
		return errorReply(mapTargetError(err))
	}
	sess.log.Printf("bp set %#x th=%d cond=%q (slots=%d)",
		addr, threshold, cond, len(sess.target.Breakpoints()))
	return "OK"
}

func (sess *Session) clearBP(s string) string {
	addr, err := parseZArg(s)
	if err != nil {
		return errorReply(ErrBPBadAddr)
	}
	if err := sess.target.ClearBreakpoint(addr); err != nil {
		return errorReply(mapTargetError(err))
	}
	sess.log.Printf("bp clear %#x (slots=%d)", addr, len(sess.target.Breakpoints()))
	return "OK"
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

// bpStatus handles "qBp": one record per installed breakpoint,
// "<addr>,<en>,<hits>,<stops>,<th>,<condhex>" joined by ";". The list lets a
// (re)connected client rebuild the exact breakpoint view: which slots exist,
// whether they are enabled, and how often they hit/stopped so far.
func (sess *Session) bpStatus() string {
	var sb strings.Builder
	sb.WriteString("bp:")
	for i, b := range sess.target.Breakpoints() {
		if i > 0 {
			sb.WriteString(";")
		}
		en := 0
		if b.Enabled {
			en = 1
		}
		sb.WriteString(fmt.Sprintf("%x,%d,%d,%d,%d,%s",
			b.Addr, en, b.Hits, b.Stops, b.Threshold, hex.EncodeToString([]byte(b.Cond))))
	}
	return sb.String()
}

// bpEnable handles "qBpEn,<addr>" / "qBpDis,<addr>".
func (sess *Session) bpEnable(arg string, on bool) string {
	addr, err := strconv.ParseUint(arg, 16, 32)
	if err != nil {
		return errorReply(ErrBPBadAddr)
	}
	if err := sess.target.EnableBreakpoint(uint32(addr), on); err != nil {
		return errorReply(mapTargetError(err))
	}
	sess.log.Printf("bp %#x enabled=%v", addr, on)
	return "OK"
}

// bpConfigure handles "qBpCfg,<addr>[,th=<n>][,cond=<hex>]": atomically
// replaces threshold and/or condition of an existing breakpoint. Keys that
// are absent keep their current value; "cond=" (empty) clears the condition.
func (sess *Session) bpConfigure(arg string) string {
	parts := strings.Split(arg, ",")
	if len(parts) < 2 {
		return errorReply(ErrBPBadAddr)
	}
	addr, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return errorReply(ErrBPBadAddr)
	}
	cur, ok := findBP(sess.target, uint32(addr))
	if !ok {
		return errorReply(ErrNoBP)
	}
	cond, threshold := cur.Cond, cur.Threshold
	for _, kv := range parts[1:] {
		k, v, found := strings.Cut(kv, "=")
		if !found {
			return errorReply(ErrBPBadAddr)
		}
		switch k {
		case "th":
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return errorReply(ErrBPBadAddr)
			}
			threshold = n
		case "cond":
			if v == "" {
				cond = ""
				continue
			}
			raw, err := hex.DecodeString(v)
			if err != nil {
				return errorReply(ErrBPBadCond)
			}
			cond = string(raw)
		default:
			return errorReply(ErrBPBadAddr)
		}
	}
	if err := sess.target.ConfigureBreakpoint(uint32(addr), cond, threshold); err != nil {
		return errorReply(mapTargetError(err))
	}
	sess.log.Printf("bp cfg %#x th=%d cond=%q", addr, threshold, cond)
	return "OK"
}

// bpBatch handles "qBpBatch,<spec>;<spec>;..." where each spec is
// "<addr>[,th=<n>][,cond=<hex>]". The whole batch is validated before any
// slot is touched: one bad spec rejects everything (atomic).
func (sess *Session) bpBatch(arg string) string {
	fields := strings.Split(arg, ";")
	specs := make([]target.BreakpointSpec, 0, len(fields))
	for _, f := range fields {
		spec, err := parseBPSpec(f)
		if err != nil {
			sess.log.Printf("reject: batch spec %q: %v", f, err)
			return errorReply(ErrBPBadAddr)
		}
		specs = append(specs, spec)
	}
	if err := sess.target.ApplyBreakpoints(specs); err != nil {
		code := mapTargetError(err)
		sess.log.Printf("reject: batch of %d -> %s (table untouched)", len(specs), errorReply(code))
		return errorReply(code)
	}
	sess.log.Printf("bp batch applied %d specs (slots=%d)", len(specs), len(sess.target.Breakpoints()))
	return "OK"
}

// parseBPSpec parses "<addr>[,th=<n>][,cond=<hex>]".
func parseBPSpec(f string) (target.BreakpointSpec, error) {
	var spec target.BreakpointSpec
	parts := strings.Split(f, ",")
	addr, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return spec, err
	}
	spec.Addr = uint32(addr)
	for _, kv := range parts[1:] {
		k, v, found := strings.Cut(kv, "=")
		if !found {
			return spec, errors.New("bad spec field")
		}
		switch k {
		case "th":
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return spec, err
			}
			spec.Threshold = n
		case "cond":
			raw, err := hex.DecodeString(v)
			if err != nil {
				return spec, err
			}
			spec.Cond = string(raw)
		default:
			return spec, errors.New("unknown spec field")
		}
	}
	return spec, nil
}
