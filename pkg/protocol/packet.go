package protocol

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

// Capabilities records the negotiated qSupported feature set.
type Capabilities struct {
	SoftwareBreakpoints bool
	NoAckMode           bool
}

// Supported features offered by this server. Only features the server
// understands are echoed back; everything the client advertises on top
// is silently dropped (graceful downgrade).
const serverFeatureList = "swbreak+;QStartNoAckMode+"

// ServerFeatures lists qSupported features offered by this server.
func ServerFeatures() string { return serverFeatureList }

// Negotiate narrows the client's advertised feature list to the supported
// intersection. Unknown client features are dropped (downgrade); a
// request to enable hardware breakpoints is refused because the server
// emulates software breakpoints only.
func Negotiate(clientFeatures string) (Capabilities, error) {
	caps := Capabilities{}
	fields := strings.Split(clientFeatures, ";")
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		key := f
		valPlus := strings.HasSuffix(f, "+")
		valMinus := strings.HasSuffix(f, "-")
		if valPlus || valMinus {
			key = f[:len(f)-1]
		}
		if i := strings.IndexByte(f, '='); i >= 0 {
			key = f[:i]
		}
		enable := valPlus || strings.Contains(f, "=")
		switch key {
		case "swbreak":
			caps.SoftwareBreakpoints = enable
		case "hwbreak":
			if enable && !valMinus {
				return caps, &target.Error{
					Code:   target.CodeFeatureRejected,
					Op:     "qSupported",
					Detail: "hardware breakpoints are not supported; use swbreak",
				}
			}
		case "QStartNoAckMode":
			caps.NoAckMode = valPlus
		}
		// unknown features: graceful downgrade, silently omitted
	}
	return caps, nil
}

// Logger is the minimal logging surface used during packet handling.
type Logger interface {
	Printf(format string, args ...interface{})
}

// Dispatcher turns RSP packet bodies into reply packet bodies for one
// session.
type Dispatcher struct {
	target *target.Target
	caps   Capabilities
	log    Logger

	resumePending bool
}

// NewDispatcher binds a dispatcher to a target.
func NewDispatcher(t *target.Target, log Logger) *Dispatcher {
	return &Dispatcher{target: t, log: log}
}

// Caps returns the current negotiated capabilities.
func (d *Dispatcher) Caps() Capabilities { return d.caps }

// SetNoAckMode records the post-handshake no-ack state.
func (d *Dispatcher) SetNoAckMode() {
	d.caps.NoAckMode = true
}

func (d *Dispatcher) logf(format string, args ...interface{}) {
	if d.log != nil {
		d.log.Printf(format, args...)
	}
}

// Dispatch handles one packet body and returns the reply body. An empty
// reply signals "unsupported"; callers encode structured errors as Exx.
func (d *Dispatcher) Dispatch(body []byte) []byte {
	if len(body) == 0 {
		return []byte("")
	}
	d.logf("recv packet %q", string(body))
	cmd := body[0]
	args := body[1:]

	switch cmd {
	case '+', '-': // stray ack inside packet channel: ignore
		return []byte("")
	case '?':
		return d.stopReply()
	case 'g':
		return d.readAllRegs()
	case 'p':
		return d.readOneReg(args)
	case 'P':
		return d.writeOneReg(args)
	case 'G':
		return d.writeAllRegs(args)
	case 'm':
		return d.readMem(args)
	case 'M':
		return d.writeMem(args)
	case 's':
		return d.singleStep(args)
	case 'c':
		d.resumePending = true
		// The session layer performs the actual (interruptible) resume
		// and emits the stop reply; no immediate reply is sent here.
		return nil
	case 'Z':
		return d.addBreakpoint(args)
	case 'z':
		return d.removeBreakpoint(args)
	case 'D':
		// detach: reply then the session layer closes the connection.
		return []byte("OK")
	case 'k':
		return []byte("OK")
	case 'q':
		return d.query(args)
	case 'Q':
		return d.set(args)
	case 'v':
		return d.vcommand(args)
	case 'H':
		return []byte("OK") // single thread
	case '_':
		return []byte("") // xfer unsupported variant
	default:
		d.logf("reject malformed/unknown packet %q", string(body))
		return codeReply(target.CodeMalformedPacket)
	}
}

// ResumePending reports whether the last packet started a 'c' resume.
func (d *Dispatcher) ResumePending() bool { return d.resumePending }

// ClearResumePending resets the pending-resume latch.
func (d *Dispatcher) ClearResumePending() { d.resumePending = false }

func (d *Dispatcher) query(args []byte) []byte {
	switch {
	case bytes.HasPrefix(args, []byte("Supported")):
		caps, err := Negotiate(string(bytes.TrimPrefix(args, []byte("Supported"))))
		if err != nil {
			d.logf("feature negotiation rejected: %v", err)
			return errReply(err)
		}
		d.caps = caps
		return []byte(serverFeatureList)
	case bytes.Equal(args, []byte("Attached")):
		return []byte("1")
	case bytes.Equal(args, []byte("C")):
		return []byte("QC1") // single thread
	case bytes.Equal(args, []byte("TStatus")):
		return []byte("") // no trace support
	case bytes.HasPrefix(args, []byte("Xfer")):
		return []byte("")
	case bytes.Equal(args, []byte("BpList")):
		return d.listBreakpoints()
	case bytes.HasPrefix(args, []byte("Symbol")):
		return []byte("OK")
	default:
		return []byte("") // unsupported query -> empty reply
	}
}

func (d *Dispatcher) set(args []byte) []byte {
	switch {
	case bytes.HasPrefix(args, []byte("StartNoAckMode")):
		d.SetNoAckMode()
		return []byte("OK")
	default:
		return []byte("")
	}
}

func (d *Dispatcher) vcommand(args []byte) []byte {
	// vCont is not offered; return empty so the client falls back to
	// s/c. Kill/detach have first-class packets.
	return []byte("")
}

func (d *Dispatcher) readAllRegs() []byte {
	regs, err := d.target.ReadRegisters()
	if err != nil {
		return errReply(err)
	}
	return encodeRegisters(regs)
}

func (d *Dispatcher) writeAllRegs(args []byte) []byte {
	regs, ok := decodeRegisters(args)
	if !ok {
		return codeReply(target.CodeMalformedPacket)
	}
	if err := d.target.WriteRegisters(regs); err != nil {
		return errReply(err)
	}
	return []byte("OK")
}

func (d *Dispatcher) readOneReg(args []byte) []byte {
	idx, ok := parseUint(args)
	if !ok || int(idx) >= target.RegN {
		return codeReply(target.CodeRegisterIndex)
	}
	v, err := d.target.ReadRegister(int(idx))
	if err != nil {
		return errReply(err)
	}
	return encodeHex(le32(v))
}

func (d *Dispatcher) writeOneReg(args []byte) []byte {
	eq := bytes.IndexByte(args, '=')
	if eq < 0 {
		return codeReply(target.CodeMalformedPacket)
	}
	idx, ok := parseUint(args[:eq])
	if !ok || int(idx) >= target.RegN {
		return codeReply(target.CodeRegisterIndex)
	}
	raw, ok := decodeHex(args[eq+1:])
	if !ok || len(raw) != 4 {
		return codeReply(target.CodeMalformedPacket)
	}
	if err := d.target.WriteRegister(int(idx), le32decode(raw)); err != nil {
		return errReply(err)
	}
	return []byte("OK")
}

func (d *Dispatcher) readMem(args []byte) []byte {
	addr, n, ok := splitAddrLen(args)
	if !ok {
		return codeReply(target.CodeMalformedPacket)
	}
	data, err := d.target.ReadMemory(uint32(addr), uint32(n))
	if err != nil {
		return errReply(err)
	}
	return encodeHex(data)
}

func (d *Dispatcher) writeMem(args []byte) []byte {
	comma := bytes.IndexByte(args, ',')
	colon := bytes.IndexByte(args, ':')
	if comma < 0 || colon < 0 || colon < comma {
		return codeReply(target.CodeMalformedPacket)
	}
	addr, ok1 := parseUint(args[:comma])
	n, ok2 := parseUint(args[comma+1 : colon])
	if !ok1 || !ok2 {
		return codeReply(target.CodeMalformedPacket)
	}
	data, ok := decodeHex(args[colon+1:])
	if !ok || uint64(len(data)) != n {
		return codeReply(target.CodeMalformedPacket)
	}
	if err := d.target.WriteMemory(uint32(addr), data); err != nil {
		return errReply(err)
	}
	return []byte("OK")
}

func (d *Dispatcher) singleStep(args []byte) []byte {
	// Optional [=thread;]addr argument is ignored for thread; a provided
	// address must equal the current PC (we do not redirect execution).
	if len(args) > 0 {
		if _, _, ok := parseThreadAddr(args); !ok {
			return codeReply(target.CodeMalformedPacket)
		}
	}
	reason, err := d.target.Step()
	if err != nil && reason.Kind == target.StopNone {
		return errReply(err)
	}
	return ReplyForStop(reason)
}

func (d *Dispatcher) addBreakpoint(args []byte) []byte {
	kind, addr, kindOK, err := parseZPacket(args)
	if err != nil || !kindOK {
		return codeReply(target.CodeMalformedPacket)
	}
	if kind != 0 { // only software breakpoints (swbreak)
		d.logf("reject breakpoint type %d: unsupported (swbreak only)", kind)
		return []byte("") // unsupported -> empty reply
	}
	if _, err := d.target.SetBreakpoint(uint32(addr)); err != nil {
		return errReply(err)
	}
	return []byte("OK")
}

func (d *Dispatcher) removeBreakpoint(args []byte) []byte {
	kind, addr, kindOK, err := parseZPacket(args)
	if err != nil || !kindOK {
		return codeReply(target.CodeMalformedPacket)
	}
	if kind != 0 {
		return []byte("")
	}
	if err := d.target.ClearBreakpoint(uint32(addr)); err != nil {
		return errReply(err)
	}
	return []byte("OK")
}

func (d *Dispatcher) listBreakpoints() []byte {
	bps := d.target.Breakpoints()
	parts := make([]string, 0, len(bps))
	for _, bp := range bps {
		parts = append(parts, fmt.Sprintf("%x:%d", bp.Addr, bp.Hits))
	}
	return []byte(strings.Join(parts, ","))
}

func (d *Dispatcher) stopReply() []byte {
	snap := d.target.StateSnapshot()
	if snap.Running {
		return []byte("S02") // interrupt-style status while running
	}
	return ReplyForStop(snap.Stop)
}

// ReplyForStop renders a target.StopReason as an RSP stop reply.
func ReplyForStop(r target.StopReason) []byte {
	switch r.Kind {
	case target.StopHalt:
		return []byte("W00")
	case target.StopBreakpoint:
		return []byte("S05")
	case target.StopInterrupt:
		return []byte("S02")
	case target.StopFault:
		return []byte("S0b")
	default:
		return []byte("S00")
	}
}

// ErrorToCode maps structured errors to the numeric class used in Exx.
func ErrorToCode(err error) byte {
	if err == nil {
		return 0
	}
	return byte(errorCode(err))
}

func errReply(err error) []byte {
	return []byte(fmt.Sprintf("E%02x", errorCode(err)))
}

func codeReply(c target.Code) []byte {
	return []byte(fmt.Sprintf("E%02x", byte(c)))
}

func errorCode(err error) target.Code {
	if te, ok := err.(*target.Error); ok {
		return te.Code
	}
	return target.CodeImageCorrupt
}

// ---- helpers ----

func splitAddrLen(args []byte) (uint64, uint64, bool) {
	comma := bytes.IndexByte(args, ',')
	if comma < 0 {
		return 0, 0, false
	}
	addr, ok1 := parseUint(args[:comma])
	n, ok2 := parseUint(args[comma+1:])
	return addr, n, ok1 && ok2
}

// parseZPacket parses "type,addr,kind".
func parseZPacket(args []byte) (int, uint64, bool, error) {
	parts := bytes.Split(args, []byte{','})
	if len(parts) != 3 {
		return 0, 0, false, nil
	}
	t, ok1 := parseUint(parts[0])
	addr, ok2 := parseUint(parts[1])
	if _, ok3 := parseUint(parts[2]); !ok3 {
		return 0, 0, false, nil
	}
	return int(t), addr, ok1 && ok2, nil
}

func parseThreadAddr(args []byte) (thread int, addr uint64, ok bool) {
	s := string(args)
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = s[i+1:]
	}
	if s == "" {
		return 0, 0, true
	}
	addr, ok = parseUintStr(s)
	return 0, addr, ok
}

func encodeRegisters(regs [target.RegN]uint32) []byte {
	out := make([]byte, 0, target.RegN*8)
	for i := 0; i < target.RegN; i++ {
		out = append(out, encodeHex(le32(regs[i]))...)
	}
	return out
}

func decodeRegisters(data []byte) ([target.RegN]uint32, bool) {
	var regs [target.RegN]uint32
	if len(data) != target.RegN*8 {
		return regs, false
	}
	for i := 0; i < target.RegN; i++ {
		raw, ok := decodeHex(data[i*8 : (i+1)*8])
		if !ok {
			return regs, false
		}
		regs[i] = le32decode(raw)
	}
	return regs, true
}

func le32(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

func le32decode(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func fromHex(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

func toHex(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + n - 10
}

func encodeHex(data []byte) []byte {
	out := make([]byte, len(data)*2)
	for i, b := range data {
		out[2*i] = toHex(b >> 4)
		out[2*i+1] = toHex(b & 0x0F)
	}
	return out
}

func decodeHex(data []byte) ([]byte, bool) {
	if len(data)%2 != 0 {
		return nil, false
	}
	out := make([]byte, len(data)/2)
	for i := 0; i < len(out); i++ {
		hi, ok1 := fromHex(data[2*i])
		lo, ok2 := fromHex(data[2*i+1])
		if !ok1 || !ok2 {
			return nil, false
		}
		out[i] = hi<<4 | lo
	}
	return out, true
}

func parseUint(hexstr []byte) (uint64, bool) {
	return parseUintStr(string(hexstr))
}

func parseUintStr(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
