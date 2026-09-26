// Command blastgate sits between AI agents and a Kubernetes API server.
// Every request is forwarded as the human who owns the agent's session;
// every write is first measured, put to the policy, and allowed, refused,
// or held until a human approves it.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// version is overwritten at release time with -ldflags "-X main.version=…".
var version = "dev"

const usage = `usage: blastgate <command>

commands:
  serve       run the proxy, the approver UI and, when configured, the observe webhook
  session     new | list | revoke
  approver    who may sign in to the UI: new --name <name> | list | revoke <id>
  approvals   list approvals [--status pending]
  approve     approve a held request: approve <id> --by <name>
  deny        deny a held request: deny <id> --by <name>
  replay      re-evaluate past decisions under a policy: replay --policy <file> [--since 168h]
  audit       export [--since 24h]: the audit trail as JSON lines
  webhook-config  print the observe-only ValidatingWebhookConfiguration: webhook-config --url https://<host>:<port>/validate
  version     print the version`

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return serveCmd(ctx, getenv, stderr)
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, usage)
		return 0
	case "session":
		return sessionCmd(args[1:], getenv, stdout, stderr)
	case "approver":
		return approverCmd(args[1:], getenv, stdout, stderr)
	case "approvals":
		return approvalsCmd(args[1:], getenv, stdout, stderr)
	case "approve", "deny":
		return decideCmd(args[0], args[1:], getenv, stdout, stderr)
	case "replay":
		return replayCmd(args[1:], getenv, stdout, stderr)
	case "audit":
		return auditCmd(args[1:], getenv, stdout, stderr)
	case "webhook-config":
		return webhookConfigCmd(args[1:], getenv, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n%s\n", args[0], usage)
		return 2
	}
}
