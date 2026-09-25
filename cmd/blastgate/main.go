// Command blastgate sits between AI agents and a Kubernetes API server.
// This build forwards every request as the human who owns the agent's
// session; scoring what a request would destroy comes next.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is overwritten at release time with -ldflags "-X main.version=…".
var version = "dev"

const usage = `usage: blastgate <command>

commands:
  serve     run the proxy
  session   new | list | revoke
  version   print the version`

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, usage)
		return 0
	case "session":
		return sessionCmd(args[1:], getenv, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n%s\n", args[0], usage)
		return 2
	}
}
