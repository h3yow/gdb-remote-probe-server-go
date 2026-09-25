// Command probe is a fully local, self-contained demonstration and smoke test
// of the remote debug probe: it builds an image, loads it into the simulated
// target, opens a session over an in-process lossy-capable transport and
// drives a scripted debug session, printing every wire frame, state
// transition and rejection reason.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/clock"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/image"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/protocol"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/session"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(1)
	}
}

// logger prints every line with a tag.
type logger struct{}

func (logger) Printf(format string, args ...any) { fmt.Printf("  | "+format+"\n", args...) }

func run() error {
	const codeAddr, ramAddr = uint32(0x1000), uint32(0x2000)

	// Build a small program:
	//   r1 = 0
	// loop@1004: r1 += 1
	//            if r1 == 0 never; store r1 to ram; jmp loop
	code := []uint32{
		target.Encode(target.OpMOVI, 1, 0, 0),
		target.Encode(target.OpADDI, 1, 0, 1), // 1004 loop head
		target.Encode(target.OpSTORE, 0, 1, uint16(ramAddr)),
		target.Encode(target.OpJMP, 0, 0, uint16(codeAddr+4)),
	}
	cb := make([]byte, len(code)*4)
	for i, w := range code {
		cb[i*4] = byte(w)
		cb[i*4+1] = byte(w >> 8)
		cb[i*4+2] = byte(w >> 16)
		cb[i*4+3] = byte(w >> 24)
	}
	raw, err := image.NewBuilder().
		BuildID("local-demo").
		BuildTime(time.Unix(1_700_000_000, 0).UTC()).
		Entry(codeAddr).
		Region(image.Region{Name: "flash", Addr: codeAddr, Data: cb, Perm: image.PermRead | image.PermExecute}).
		Region(image.Region{Name: "ram", Addr: ramAddr, Data: make([]byte, 16), Perm: image.PermRead | image.PermWrite}).
		Symbol(image.Symbol{Name: "loop", Addr: codeAddr + 4, Size: 12}).
		Build()
	if err != nil {
		return err
	}
	im, err := image.Load(raw)
	if err != nil {
		return err
	}
	fmt.Printf("loaded image: %d regions, %d symbols, build=%s\n",
		len(im.Regions), len(im.Symbols), im.BuildID)

	tg, err := target.New(im)
	if err != nil {
		return err
	}
	tg.SetInstructionBudget(0) // run until a trap/interrupt
	defer tg.Close()

	clk := clock.NewRealClock()
	cfg := session.Config{
		IdleTimeout: 0,
		Link:        protocol.LinkOptions{AckTimeout: 50 * time.Millisecond, MaxRetries: 3, Clock: clk},
		Clock:       clk,
		Logger:      logger{},
	}
	srv := session.New(tg, cfg)
	defer srv.Close()

	srvConn, cliConn := protocol.NewPipe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServeConn(srvConn) }()

	link := protocol.NewLink(cliConn, cfg.Link)
	defer link.Close()

	call := func(req string) string {
		fmt.Printf("> %s\n", req)
		if err := link.Send([]byte(req)); err != nil {
			fmt.Printf("< send error: %v\n", err)
			return ""
		}
		b, err := link.Recv()
		if err != nil {
			fmt.Printf("< recv error: %v\n", err)
			return ""
		}
		fmt.Printf("< %s\n", string(b))
		return string(b)
	}

	fmt.Println("== capability negotiation ==")
	call("qSupported:swbreak+;hwbreak+;qXfer:memory-map+")

	fmt.Println("== initial state ==")
	call("?")
	call("p1")

	fmt.Println("== set breakpoint at loop and run ==")
	call("Z1,1004,4")
	call("c") // hits immediately (r1 increments on resume)
	call("p1")
	call("m2000,4") // stored value

	fmt.Println("== iterate twice more ==")
	call("c")
	call("p1")
	call("c")
	call("p1")

	fmt.Println("== illegal access rejected (read-only flash write) ==")
	call("M1000,4:00000000")

	fmt.Println("== symbol lookup ==")
	call("qSymbol:6c6f6f70") // hex("loop")

	fmt.Println("== clear breakpoint, interrupt a running continue ==")
	call("z1,1004,4")
	stopped := make(chan string, 1)
	go func() {
		_ = link.Send([]byte("c"))
		b, _ := link.Recv()
		stopped <- string(b)
	}()
	time.Sleep(30 * time.Millisecond) // let it run (deterministic VM; tiny yield)
	_ = link.SendCtrl(protocol.ByteCtrlC)
	fmt.Printf("< %s (after ctrl-c)\n", <-stopped)
	call("p1")

	fmt.Println("== detach ==")
	call("D")
	if err := <-serveErr; err != nil {
		fmt.Printf("serve returned: %v\n", err)
	}
	fmt.Println("demo complete")
	return nil
}
