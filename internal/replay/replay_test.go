package replay

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/normalize"
	"github.com/SaiPisey2/blastgate/internal/policy"
	"github.com/SaiPisey2/blastgate/internal/store"
)

func decisionRow(at time.Time, id string, a normalize.Action, i engine.Impact, labels map[string]string, rule, decision string) store.AuditRow {
	act, _ := json.Marshal(a)
	imp, _ := json.Marshal(i)
	lab, _ := json.Marshal(labels)
	return store.AuditRow{
		At: at, Kind: "decision", RequestID: id, Session: "sess-1", Human: "alice", Agent: "coding-agent",
		Verb: a.Verb, Resource: a.Resource, Namespace: a.Namespace, Name: a.Name,
		ActionJSON: act, ImpactJSON: imp, LabelsJSON: lab,
		Class: i.Class, Measured: i.Measured, Rule: rule, Decision: decision,
	}
}

// seedDecisions is one TERMINAL delete the default policy held and one
// REVERSIBLE patch it allowed, whose namespace labels were unknown -- the
// same fixture the CLI's replay tests use, at package level.
func seedDecisions() []store.AuditRow {
	now := time.Now().UTC()
	return []store.AuditRow{
		decisionRow(now.Add(-2*time.Minute), "r1",
			normalize.Action{Verb: "delete", Resource: "persistentvolumeclaims", Namespace: "demo", Name: "data"},
			engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1, Undo: "none"},
			map[string]string{}, "data-destruction", "hold"),
		decisionRow(now.Add(-time.Minute), "r2",
			normalize.Action{Verb: "patch", Resource: "configmaps", Namespace: "demo", Name: "settings"},
			engine.Impact{Class: engine.ClassReversible, Measured: true, Undo: "patch"},
			nil, "safe", "allow"),
	}
}

const allowEverything = `rules:
  - name: everything
    when: "true"
    then: allow
default: allow
unmeasured: hold
`

func loadPolicy(t *testing.T, text string) *policy.Policy {
	t.Helper()
	p, err := policy.Load([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReplayCountsChanges(t *testing.T) {
	res := Run(context.Background(), seedDecisions(), loadPolicy(t, allowEverything))
	if res.Evaluated != 2 || res.Changed != 1 || len(res.Changes) != 1 {
		t.Fatalf("res = %+v", res)
	}
	c := res.Changes[0]
	if c.RequestID != "r1" || c.Verb != "delete" || c.Resource != "persistentvolumeclaims" ||
		c.Namespace != "demo" || c.Name != "data" ||
		c.RuleBefore != "data-destruction" || c.RuleAfter != "everything" ||
		c.DecisionBefore != "hold" || c.DecisionAfter != "allow" {
		t.Errorf("change = %+v", c)
	}
}

// Stored labels of JSON null are "unknown", and must replay as unknown: a
// rule reading them errors and holds, as it did live. Replaying them as
// "no labels" would report a hold as an allow.
func TestReplayPassesUnknownLabelsAsUnknown(t *testing.T) {
	p := loadPolicy(t, `rules:
  - name: prod-is-held
    when: '"env" in ns.labels && ns.labels.env == "prod"'
    then: hold
default: allow
unmeasured: hold
`)
	res := Run(context.Background(), seedDecisions(), p)
	// r1's labels are known and empty: the rule is false, so it moves from
	// hold to allow. r2's are unknown: the rule errors and holds. Were r2
	// replayed with empty labels it too would allow, and not change.
	if res.Evaluated != 2 || res.Changed != 2 {
		t.Fatalf("res = %+v", res)
	}
	var r2 *Change
	for i := range res.Changes {
		if res.Changes[i].RequestID == "r2" {
			r2 = &res.Changes[i]
		}
	}
	if r2 == nil {
		t.Fatalf("no change for r2: %+v", res.Changes)
	}
	if r2.RuleBefore != "safe" || r2.RuleAfter != "error:prod-is-held" ||
		r2.DecisionBefore != "allow" || r2.DecisionAfter != "hold" {
		t.Errorf("r2 change = %+v", *r2)
	}
}

// A decision row with no stored impact (or action, or labels) was never
// scored -- a request refused as unparseable -- so there is nothing a
// policy could be evaluated against, and it is counted apart (Skipped)
// rather than guessed at.
func TestReplaySkipsUnscoredRows(t *testing.T) {
	rows := append(seedDecisions(), store.AuditRow{
		At: time.Now().UTC(), Kind: "decision", RequestID: "r3",
		Verb: "delete", Resource: "pods", Rule: "data-destruction", Decision: "hold",
		// ActionJSON, ImpactJSON and LabelsJSON deliberately left empty:
		// this row was never scored.
	})
	res := Run(context.Background(), rows, loadPolicy(t, allowEverything))
	if res.Skipped != 1 {
		t.Fatalf("skipped = %d, want 1: %+v", res.Skipped, res)
	}
	if res.Evaluated != 2 {
		t.Fatalf("evaluated = %d, want 2 (r3 must not count): %+v", res.Evaluated, res)
	}
	for _, c := range res.Changes {
		if c.RequestID == "r3" {
			t.Errorf("unscored row r3 produced a change: %+v", c)
		}
	}
}
