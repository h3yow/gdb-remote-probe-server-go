// Command probe runs the local GDB-remote-compatible debug probe server,
// or generates a reproducible sample image with "init-image".
package main

import "os"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int { return 0 }
