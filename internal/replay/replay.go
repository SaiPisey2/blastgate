// Package replay re-evaluates recorded decisions under a candidate policy,
// so an operator (the CLI's "replay" command, and the admin API) sees what
// a policy change would have done before making it. It evaluates exactly
// what the gate evaluated -- the stored action, impact and namespace
// labels -- and compares policy decision with policy decision (ruling
// P1-R15): the stored Decision is the policy's, even for a hold an
// approval later released.
package replay

import (
	"context"
	"encoding/json"
	"time"

	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/normalize"
	"github.com/SaiPisey2/blastgate/internal/policy"
	"github.com/SaiPisey2/blastgate/internal/store"
)

// Change is one stored decision the candidate policy would have made
// differently. Resource carries the subresource too (as
// "resource/subresource") since a Change has no separate field for it.
type Change struct {
	At             time.Time `json:"at"`
	RequestID      string    `json:"request_id"`
	Verb           string    `json:"verb"`
	Resource       string    `json:"resource"`
	Namespace      string    `json:"namespace"`
	Name           string    `json:"name"`
	RuleBefore     string    `json:"rule_before"`
	RuleAfter      string    `json:"rule_after"`
	DecisionBefore string    `json:"decision_before"`
	DecisionAfter  string    `json:"decision_after"`
}

// MaxChanges bounds how many Changes a Result lists. Changed still counts
// every one: a candidate policy that flips a week of decisions must not
// make one replay hold a week of Change values in memory.
const MaxChanges = 500

// Result is the outcome of replaying a batch of stored decisions under a
// candidate policy. Truncated is set by the caller, not by Run: it means
// the window held more decision rows than the caller fetched and passed
// in, so Evaluated covers only the most recent of them (P2-R21).
type Result struct {
	Evaluated int      `json:"evaluated"`
	Changed   int      `json:"changed"`
	Skipped   int      `json:"skipped"`
	Truncated bool     `json:"truncated"`
	Changes   []Change `json:"changes"`
}

// Run re-evaluates every row in rows under p and reports what would
// change. rows must already be "decision" rows (the caller's query, as
// AuditSince(kind="decision") does); of those, only the ones that were
// actually scored count toward Evaluated -- a decision row with no stored
// impact was never scored (a request refused as unparseable), so there is
// nothing a policy could be evaluated against, and it is counted apart
// (Skipped) rather than guessed. Labels of JSON null decode to a nil map:
// unknown, exactly as the gate saw them, so a rule reading them holds here
// as it did live.
//
// Only the first MaxChanges changes are listed; Changed counts them all.
// A cancelled ctx stops the loop and returns ctx's error with the partial
// result, which the caller must not present as complete.
func Run(ctx context.Context, rows []store.AuditRow, p *policy.Policy) (Result, error) {
	var res Result
	for _, r := range rows {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		var a normalize.Action
		var imp engine.Impact
		var labels map[string]string
		if len(r.ActionJSON) == 0 || len(r.ImpactJSON) == 0 || len(r.LabelsJSON) == 0 ||
			json.Unmarshal(r.ActionJSON, &a) != nil || json.Unmarshal(r.ImpactJSON, &imp) != nil ||
			json.Unmarshal(r.LabelsJSON, &labels) != nil {
			res.Skipped++
			continue
		}
		res.Evaluated++
		v := p.Evaluate(ctx, a, imp, labels)
		if string(v.Decision) == r.Decision {
			continue
		}
		res.Changed++
		if len(res.Changes) >= MaxChanges {
			continue
		}
		resource := r.Resource
		if r.Subresource != "" {
			resource += "/" + r.Subresource
		}
		res.Changes = append(res.Changes, Change{
			At:             r.At,
			RequestID:      r.RequestID,
			Verb:           r.Verb,
			Resource:       resource,
			Namespace:      r.Namespace,
			Name:           r.Name,
			RuleBefore:     r.Rule,
			RuleAfter:      v.Rule,
			DecisionBefore: r.Decision,
			DecisionAfter:  string(v.Decision),
		})
	}
	return res, nil
}
