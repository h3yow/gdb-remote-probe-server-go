package protocol

import (
	"strings"
	"testing"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

type testLog struct{ t *testing.T }

func (l testLog) Printf(format string, args ...interface{}) {
	l.t.Logf(format, args...)
}

func dispatcher(t *testing.T) (*target.Target, *Dispatcher) {
	t.Helper()
	p := target.NewProgram().
		Movi(target.RegR0, 7).
		St(0x20, target.RegR0).
		Label("loop").
		Jmp("loop")
	img, err := target.BuildImage(p, 0, 0x20, []byte{0, 0, 0, 0}, true)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := target.NewTarget(img, target.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	return tg, NewDispatcher(tg, testLog{t})
}

func TestNegotiationDowngradeAndReject(t *testing.T) {
	// Unknown features are dropped; known ones accepted.
	caps, err := Negotiate("swbreak+;qXfer:features+;fork-events+")
	if err != nil || !caps.SoftwareBreakpoints {
		t.Fatalf("negotiate: %+v %v", caps, err)
	}
	if strings.Contains(ServerFeatures(), "fork-events") {
		t.Fatal("server must not echo unsupported features")
	}
	// Hardware breakpoints must be explicitly rejected.
	if _, err := Negotiate("hwbreak+"); err == nil || target.CodeOf(err) != target.CodeFeatureRejected {
		t.Fatalf("want feature rejection, got %v", err)
	}
}

func TestRegPackets(t *testing.T) {
	tg, d := dispatcher(t)
	// g: all registers initially pc=0
	got := d.Dispatch([]byte("g"))
	if string(got) != strings.Repeat("00000000", target.RegN) {
		t.Fatalf("g = %q", got)
	}
	// P0=f..
	if r := d.Dispatch([]byte("P0=0f000000")); string(r) != "OK" {
		t.Fatalf("P0: %q", r)
	}
	v, _ := tg.ReadRegister(0)
	if v != 0x0f {
		t.Fatalf("r0 = %#x", v)
	}
	// p0
	if r := d.Dispatch([]byte("p0")); string(r) != "0f000000" {
		t.Fatalf("p0 = %q", r)
	}
	// bad register
	if r := d.Dispatch([]byte("p9")); string(r) != "E0c" {
		t.Fatalf("p9 = %q want E0c", r)
	}
}

func TestMemoryPacketsAndErrors(t *testing.T) {
	_, d := dispatcher(t)
	// malformed m packet
	if r := string(d.Dispatch([]byte("m0"))); r != "E14" {
		t.Fatalf("malformed m: %q", r)
	}
	// read .text (4 bytes = first instruction movi r0,7)
	if r := string(d.Dispatch([]byte("m0,4"))); r != "02000700" {
		t.Fatalf("m0,4 = %q", r)
	}
	// write to R-X text -> E08 (read-only)
	if r := string(d.Dispatch([]byte("M0,4:00000000"))); r != "E08" {
		t.Fatalf("write text: %q want E08", r)
	}
	// valid data write
	if r := string(d.Dispatch([]byte("M20,4:01020304"))); r != "OK" {
		t.Fatalf("write data: %q", r)
	}
	// out of range
	if r := string(d.Dispatch([]byte("m9000,4"))); r != "E07" {
		t.Fatalf("oor: %q want E07", r)
	}
}

func TestStepAndBreakpointPackets(t *testing.T) {
	tg, d := dispatcher(t)
	// set bp at instruction 2 (0x04)
	if r := string(d.Dispatch([]byte("Z0,4,0"))); r != "OK" {
		t.Fatalf("Z: %q", r)
	}
	// idempotent set
	if r := string(d.Dispatch([]byte("Z0,4,0"))); r != "OK" {
		t.Fatalf("Z dup: %q", r)
	}
	// hardware breakpoint type unsupported -> empty
	if r := d.Dispatch([]byte("Z1,4,0")); len(r) != 0 {
		t.Fatalf("hw bp should be unsupported empty, got %q", r)
	}
	// limit/align/misaligned codes
	_, _ = dispatcher(t)
	for _, a := range []string{"Z0,1,0", "Z0,20,0"} {
		r := string(d.Dispatch([]byte(a)))
		if r == "OK" {
			t.Fatalf("%s expected failure", a)
		}
	}
	// single step -> moves pc to 4, hits bp after second step
	if r := string(d.Dispatch([]byte("s"))); r != "S05" {
		t.Fatalf("step1 = %q want S05", r)
	}
	pc, _ := tg.ReadRegister(target.RegPC)
	if pc != 4 {
		t.Fatalf("pc after step = %#x", pc)
	}
	// step bp landed; clear is idempotent
	if r := string(d.Dispatch([]byte("z0,4,0"))); r != "OK" {
		t.Fatalf("z: %q", r)
	}
	if r := string(d.Dispatch([]byte("z0,4,0"))); r != "OK" {
		t.Fatalf("z dup: %q", r)
	}
}

func TestContinueIsAsyncPending(t *testing.T) {
	tg, d := dispatcher(t)
	r := d.Dispatch([]byte("c"))
	if r != nil || !d.ResumePending() {
		t.Fatalf("c should set pending with no reply, got %q", r)
	}
	d.ClearResumePending()
	// Session layer performs the actual resume.
	if err := tg.Resume(); err != nil {
		t.Fatal(err)
	}
	if err := tg.Interrupt(); err != nil {
		t.Fatal(err)
	}
	reason := tg.WaitStopped()
	if reason.Kind != target.StopInterrupt {
		t.Fatalf("want interrupt, got %+v", reason)
	}
	if r := ReplyForStop(reason); string(r) != "S02" {
		t.Fatalf("reply = %q", r)
	}
}

func TestUnknownAndNoAckPackets(t *testing.T) {
	_, d := dispatcher(t)
	if r := d.Dispatch([]byte("xxxx")); string(r) != "E14" {
		t.Fatalf("unknown = %q", r)
	}
	if r := d.Dispatch([]byte("QStartNoAckMode")); string(r) != "OK" {
		t.Fatalf("noack = %q", r)
	}
	if !d.Caps().NoAckMode {
		t.Fatal("caps should reflect no-ack mode")
	}
	if r := d.Dispatch([]byte("?")); string(r) != "S00" {
		t.Fatalf("? on fresh target = %q", r)
	}
}
