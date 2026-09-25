package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/SaiPisey2/blastgate/internal/approval"
	"github.com/SaiPisey2/blastgate/internal/config"
	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/store"
)

// pendingTTL is how long a pending approval can be decided, and how long a
// denial keeps blocking retries of the same request (global constraint).
const pendingTTL = time.Hour

// approvalsCmd lists approvals, newest first. The summary is recomputed
// from the stored impact, so it reads the same as the ticket the agent got.
func approvalsCmd(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("approvals", flag.ContinueOnError)
	fs.SetOutput(stderr)
	status := fs.String("status", "", "only approvals in this state (pending, approved, denied, consumed, superseded, expired)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: blastgate approvals [--status pending]")
		return 2
	}
	cfg, err := config.LoadLocal(getenv)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	st, err := openStore(cfg.DataDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer st.Close()
	l, err := st.ListApprovals(context.Background(), *status)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	now := time.Now()
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tAGE\tHUMAN\tAGENT\tRULE\tSUMMARY\tSTATUS")
	for _, a := range l {
		var imp engine.Impact
		summary := "unknown impact"
		if json.Unmarshal(a.ImpactJSON, &imp) == nil {
			summary = imp.Summary()
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", safe(a.ID), age(now.Sub(a.Created)),
			safe(a.Human), safe(a.Agent), safe(a.Rule), summary, safe(a.Status))
	}
	tw.Flush()
	return 0
}

// decideCmd is approve and deny. The id may come before or after --by.
func decideCmd(verb string, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	usage := fmt.Sprintf("usage: blastgate %s <id> --by <name>", verb)
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	by := fs.String("by", "", "who is deciding (required); recorded with the decision")
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	id := positional[0]
	if err := validateApprover(*by); err != nil {
		fmt.Fprintf(stderr, "%v\n%s\n", err, usage)
		return 2
	}
	cfg, err := config.LoadSigning(getenv)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	st, err := openStore(cfg.DataDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer st.Close()
	svc := &approval.Service{Store: st, Key: cfg.SigningKey, TokenTTL: cfg.ApprovalTTL, PendingTTL: pendingTTL, Now: time.Now}
	ctx := context.Background()
	var a store.Approval
	if verb == "approve" {
		a, err = svc.Approve(ctx, id, *by)
	} else {
		a, err = svc.Deny(ctx, id, *by)
	}
	if err != nil {
		return decideFailed(ctx, st, svc, id, err, stderr)
	}
	switch verb {
	case "approve":
		fmt.Fprintf(stdout, "approval %s approved by %s; the agent's retry of the same request will be forwarded if it is retried before %s and its impact has not changed\n",
			a.ID, *by, a.Expires.Local().Format(time.RFC3339))
	default:
		fmt.Fprintf(stdout, "approval %s denied by %s; retries of the same request are refused until %s\n",
			a.ID, *by, a.Expires.Local().Format(time.RFC3339))
	}
	return 0
}

// decideFailed tells a refusal (unknown id, not pending, expired, or a
// concurrent decision won) from blastgate failing. The service's
// wrong-state errors are not typed, so the row is read again to classify.
func decideFailed(ctx context.Context, st *store.Store, svc *approval.Service, id string, err error, stderr io.Writer) int {
	if errors.Is(err, store.ErrNotFound) {
		fmt.Fprintf(stderr, "no approval %s\n", safe(id))
		return 2
	}
	if errors.Is(err, store.ErrConflict) {
		fmt.Fprintf(stderr, "approval %s was decided by someone else first\n", safe(id))
		return 2
	}
	a, rerr := st.ApprovalByID(ctx, id)
	if rerr == nil && (a.Status != "pending" || svc.Now().After(a.Expires)) {
		fmt.Fprintln(stderr, err)
		return 2
	}
	fmt.Fprintln(stderr, err)
	return 1
}

// validateApprover holds an approver's name to the rules a session's human
// meets: printable ASCII without spaces, at most 253 bytes. It is recorded
// beside humans in the audit trail and printed to terminals, so it must
// not carry escape sequences or look like two names.
func validateApprover(by string) error {
	if by == "" {
		return errors.New("--by is required: who is making this decision")
	}
	if len(by) > 253 {
		return errors.New("--by longer than 253 bytes")
	}
	for i := 0; i < len(by); i++ {
		if c := by[i]; c < 0x21 || c > 0x7e {
			return fmt.Errorf("--by %s may contain only printable ASCII without spaces", strconv.QuoteToASCII(by))
		}
	}
	return nil
}

// parseInterspersed parses flags wherever they appear among the positional
// arguments: `approve <id> --by bob` reads naturally, and the standard
// flag package would stop at <id> and leave --by unparsed.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		if n := len(args) - len(rest); n > 0 && args[n-1] == "--" {
			// Everything after "--" is positional, flag-shaped or not.
			return append(positional, rest...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// safe returns s unchanged when it is printable ASCII without spaces, and
// quoted otherwise. Values read back from the database are printed to an
// operator's terminal; the database is the trail, not a trusted source of
// terminal-safe text.
func safe(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e {
			return strconv.QuoteToASCII(s)
		}
	}
	return s
}

func age(d time.Duration) string {
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d/time.Second)) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + "h"
	}
	return strconv.Itoa(int(d/(24*time.Hour))) + "d"
}
