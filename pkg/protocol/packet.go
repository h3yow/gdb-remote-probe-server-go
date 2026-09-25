package protocol

// Capabilities records the negotiated qSupported feature set.
type Capabilities struct {
	SoftwareBreakpoints bool
	NoAckMode           bool
}

// ServerFeatures lists qSupported features offered by this server.
func ServerFeatures() string { return "" }

// Negotiate narrows the client's advertised feature list to the supported
// intersection. Features advertised only by the client are silently
// dropped (graceful downgrade). A mandatory feature mismatch is reported
// as an error with CodeFeatureRejected by the caller via ParseError.
func Negotiate(clientFeatures string) Capabilities { return Capabilities{} }

// TargetView is the subset of target operations the command dispatcher
// needs. *target.Target satisfies it.
type TargetView interface {
	IsRunning() bool
	ReadMemory(addr, length uint32) ([]byte, error)
	WriteMemory(addr uint32, data []byte) error
	ReadRegister(i int) (uint32, error)
	WriteRegister(i int, v uint32) error
	ReadRegisters() ([9]uint32, error)
	WriteRegisters(regs [9]uint32) error
	SetBreakpoint(addr uint32) (interface{}, error)
	ClearBreakpoint(addr uint32) error
	Breakpoints() []interface{}
	Step() (interface{}, error)
	Resume() error
	Interrupt() error
	WaitStopped() interface{}
	StateSnapshot() interface{}
	Image() interface{}
}

// Logger is the minimal logging surface used during packet handling.
type Logger interface {
	Printf(format string, args ...interface{})
}

// Dispatcher turns RSP packet bodies into reply packet bodies for one
// session. Continue ('c') is asynchronous: the dispatcher merely records
// the pending resume; the session layer drives the target and emits the
// stop reply after WaitStopped.
type Dispatcher struct {
	target TargetView
	caps   Capabilities
	log    Logger

	resumePending bool
}

// NewDispatcher binds a dispatcher to a target.
func NewDispatcher(t TargetView, log Logger) *Dispatcher { return nil }

// Caps returns the current negotiated capabilities.
func (d *Dispatcher) Caps() Capabilities { return Capabilities{} }

// SetNoAckMode is called after a successful QStartNoAckMode exchange.
func (d *Dispatcher) SetNoAckMode() {}

// Dispatch handles one packet body and returns the reply body. An empty
// reply is encoded as an empty packet (unsupported); errors are encoded
// as Exx packets by the caller.
func (d *Dispatcher) Dispatch(body []byte) []byte { return nil }

// BeginContinue marks the target as continuing. It is called by the
// session layer before ReplyForStop.
func (d *Dispatcher) BeginContinue() {}

// ReplyForStop renders a target.StopReason as an RSP stop reply.
func (d *Dispatcher) ReplyForStop(reason interface{}) []byte { return nil }

// ErrorToCode maps a target/protocol error to its stable numeric code
// used in Exx replies.
func ErrorToCode(err error) byte { return 0 }

// hex helpers

func fromHex(b byte) (byte, bool) { return 0, false }
func toHex(n byte) byte           { return 0 }
func encodeHex(data []byte) []byte { return nil }
func decodeHex(data []byte) ([]byte, bool) { return nil, false }
func parseUint(hexstr []byte) (uint64, bool) { return 0, false }
