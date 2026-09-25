package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/SaiPisey2/blastgate/internal/config"
	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/normalize"
	"github.com/SaiPisey2/blastgate/internal/policy"
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
	var n, skipped int
	var changes []string
	for _, r := range rows {
		var a normalize.Action
		var imp engine.Impact
		var labels map[string]string
		// A decision row with no stored impact was never scored (a request
		// refused as unparseable): there is nothing a policy could be
		// evaluated against, so it is counted apart rather than guessed.
		// Labels of JSON null decode to a nil map: unknown, exactly as the
		// gate saw them, so a rule reading them holds here as it did live.
		if len(r.ActionJSON) == 0 || len(r.ImpactJSON) == 0 || len(r.LabelsJSON) == 0 ||
			json.Unmarshal(r.ActionJSON, &a) != nil || json.Unmarshal(r.ImpactJSON, &imp) != nil ||
			json.Unmarshal(r.LabelsJSON, &labels) != nil {
			skipped++
			continue
		}
		n++
		v := pol.Evaluate(ctx, a, imp, labels)
		if string(v.Decision) == r.Decision {
			continue
		}
		target := safe(r.Name)
		if r.Namespace != "" {
			target = safe(r.Namespace) + "/" + target
		}
		resource := safe(r.Resource)
		if r.Subresource != "" {
			resource += "/" + safe(r.Subresource)
		}
		changes = append(changes, fmt.Sprintf("%s %s→%s %s→%s %s %s %s",
			r.At.Local().Format(time.RFC3339), safe(r.Rule), safe(v.Rule), safe(r.Decision), v.Decision,
			safe(r.Verb), resource, target))
	}
	fmt.Fprintf(stdout, "%d decisions re-evaluated; %d would change\n", n, len(changes))
	if skipped > 0 {
		fmt.Fprintf(stdout, "%d decisions skipped: never scored, nothing to evaluate\n", skipped)
	}
	for _, c := range changes {
		fmt.Fprintln(stdout, c)
	}
	return 0
}

// loadPolicy reads and parses a policy file. Every error names the file:
// serve refuses to start on it, and "policy invalid" alone would not say
// which of an operator's files to fix.
func loadPolicy(path string) (*policy.Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	p, err := policy.Load(b)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	return p, nil
}
