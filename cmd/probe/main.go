// Command probe runs the local GDB-remote-compatible debug probe server,
// or generates a reproducible sample image with "init-image".
//
// Usage:
//
//	probe init-image -out sample.img [-stripped]
//	probe serve      -image sample.img [-listen 127.0.0.1:7000] [-idle 30s]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/h3yow/gdb-remote-probe-server-go/pkg/server"
	"github.com/h3yow/gdb-remote-probe-server-go/pkg/target"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "init-image":
		return cmdInitImage(args[1:])
	case "serve":
		return cmdServe(args[1:])
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `probe - local reproducible GDB-remote debug probe

Commands:
  init-image -out FILE [-stripped]
      Generate the deterministic sample target image used for local
      verification.
  serve -image FILE [-listen ADDR] [-idle DURATION]
      Load the image and serve the GDB RSP protocol. Only one debug
      session is active at a time.
`)
}

// sampleProgram is the same fixture exercised by the test suite: it
// computes a value, stores it into a writable data segment and then loops
// so a debugger can observe registers, memory, breakpoints and interrupt.
func sampleProgram() *target.Program {
	return target.NewProgram().
		Movi(target.RegR0, 7).
		Movi(target.RegR1, 35).
		Add(target.RegR2, target.RegR1, target.RegR0). // r2 = 42
		St(0x20, target.RegR2).
		Label("loop").
		Jmp("loop")
}

func cmdInitImage(args []string) int {
	fs := flag.NewFlagSet("init-image", flag.ContinueOnError)
	out := fs.String("out", "sample.img", "output image path")
	stripped := fs.Bool("stripped", false, "emit a stripped image without symbols")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	img, err := target.BuildImage(sampleProgram(), 0x0000, 0x0020, []byte{0, 0, 0, 0}, *stripped)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build image: %v\n", err)
		return 1
	}
	if err := target.WriteImage(*out, img); err != nil {
		fmt.Fprintf(os.Stderr, "write image: %v\n", err)
		return 1
	}
	fmt.Printf("wrote %s (entry=%#04x, stripped=%v)\n", *out, img.Entry, *stripped)
	return 0
}

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	image := fs.String("image", "sample.img", "target image path")
	listen := fs.String("listen", "127.0.0.1:7000", "listen address")
	idle := fs.Duration("idle", 0, "optional idle session timeout (e.g. 30s)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logger := log.New(os.Stdout, "probe: ", log.LstdFlags|log.Lmicroseconds)
	srv, err := server.New(server.Config{
		ImagePath:   *image,
		TargetName:  "target0",
		Listen:      *listen,
		IdleTimeout: *idle,
		Log:         stdAdapter{l: logger},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "load image: %v\n", err)
		return 1
	}
	defer func() { _ = srv.Close() }()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	logger.Printf("serving image %s on %s (idle-timeout=%s)", *image, *listen, time.Duration(0).String())
	if err := srv.Listen(ctx); err != nil {
		logger.Printf("listen ended: %v", err)
		return 1
	}
	return 0
}

type stdAdapter struct{ l *log.Logger }

func (s stdAdapter) Printf(format string, args ...interface{}) {
	s.l.Printf(format, args...)
}
