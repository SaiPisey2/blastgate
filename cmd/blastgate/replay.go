package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/SaiPisey2/blastgate/internal/config"
	"github.com/SaiPisey2/blastgate/internal/policy"
	"github.com/SaiPisey2/blastgate/internal/replay"
)

// replayCmd re-evaluates recorded decisions under a candidate policy, so
// an operator sees what a policy change would have done before making it.
// It evaluates exactly what the gate evaluated -- the stored action,
// impact and namespace labels -- and compares policy decision with policy
// decision (ruling P1-R15): the stored Decision is the policy's, even for
// a hold an approval later released.
func replayCmd(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("policy", "", "the candidate policy file (required)")
	since := fs.Duration("since", 168*time.Hour, "how far back to replay")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" || fs.NArg() != 0 || *since <= 0 {
		fmt.Fprintln(stderr, "usage: blastgate replay --policy <file> [--since 168h]")
		return 2
	}
	pol, err := loadPolicy(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
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
	ctx := context.Background()
	rows, err := st.AuditSince(ctx, time.Now().Add(-*since), "decision")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	res, err := replay.Run(ctx, rows, pol)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "%d decisions re-evaluated; %d would change\n", res.Evaluated, res.Changed)
	if res.Skipped > 0 {
		fmt.Fprintf(stdout, "%d decisions skipped: never scored, nothing to evaluate\n", res.Skipped)
	}
	// Run lists at most replay.MaxChanges; without this line a count of
	// 900 above a list of 500 would read as 400 changes gone missing.
	if res.Changed > len(res.Changes) {
		fmt.Fprintf(stdout, "listing the first %d changes\n", len(res.Changes))
	}
	for _, c := range res.Changes {
		target := safe(c.Name)
		if c.Namespace != "" {
			target = safe(c.Namespace) + "/" + target
		}
		fmt.Fprintf(stdout, "%s %s→%s %s→%s %s %s %s\n",
			c.At.Local().Format(time.RFC3339), safe(c.RuleBefore), safe(c.RuleAfter), safe(c.DecisionBefore), c.DecisionAfter,
			safe(c.Verb), safe(c.Resource), target)
	}
	return 0
}

// loadPolicy reads and parses a policy file. Every error names the file:
// serve refuses to start on it, and "policy invalid" alone would not say
// which of an operator's files to fix.
func loadPolicy(path string) (*policy.Policy, error) {
	p, _, err := readPolicy(path)
	return p, err
}

// readPolicy is loadPolicy returning the text it parsed as well. serve
// shows that text in the UI's policy view: the very bytes in force, not
// the file re-read later after someone has edited it.
func readPolicy(path string) (*policy.Policy, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("policy %s: %w", path, err)
	}
	p, err := policy.Load(b)
	if err != nil {
		return nil, nil, fmt.Errorf("policy %s: %w", path, err)
	}
	return p, b, nil
}
