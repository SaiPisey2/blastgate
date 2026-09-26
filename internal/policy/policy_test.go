package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/normalize"
)

var del = normalize.Action{Verb: "delete", Resource: "pods", Namespace: "demo", Name: "web-1"}

func eval(t *testing.T, p *Policy, a normalize.Action, i engine.Impact, labels map[string]string) Verdict {
	t.Helper()
	return p.Evaluate(context.Background(), a, i, labels)
}

func TestDefaultHoldsDataDestruction(t *testing.T) {
	v := eval(t, Default(), del, engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1}, nil)
	if v.Decision != Hold || v.Rule != "data-destruction" {
		t.Errorf("verdict = %+v", v)
	}
}

func TestDefaultAllowsAReversibleMeasuredDelete(t *testing.T) {
	v := eval(t, Default(), del, engine.Impact{Class: engine.ClassReversible, Measured: true}, map[string]string{})
	if v.Decision != Allow || v.Rule != "safe" {
		t.Errorf("verdict = %+v", v)
	}
}

func TestDefaultHoldsAnEmptiedServiceOnlyInProd(t *testing.T) {
	i := engine.Impact{Class: engine.ClassReversible, Measured: true, EndpointsLeft: map[string]int{"web": 0}}
	if v := eval(t, Default(), del, i, map[string]string{"env": "prod"}); v.Decision != Hold || v.Rule != "leaves-a-service-empty-in-prod" {
		t.Errorf("prod verdict = %+v", v)
	}
	if v := eval(t, Default(), del, i, map[string]string{"env": "dev"}); v.Decision != Allow {
		t.Errorf("dev verdict = %+v", v)
	}
}

func TestDefaultPolicyDoesNotErrorOnUnlabelledNamespace(t *testing.T) {
	i := engine.Impact{Class: engine.ClassReversible, Measured: true, EndpointsLeft: map[string]int{"web": 0}}
	v := eval(t, Default(), del, i, map[string]string{})
	if strings.HasPrefix(v.Rule, "error:") {
		t.Errorf("default policy errored on an unlabelled namespace: %+v", v)
	}
}

func TestUnmeasuredHoldsEvenWhenNoRuleMatches(t *testing.T) {
	v := eval(t, Default(), del, engine.Unmeasured("x"), nil)
	if v.Decision != Hold || v.Rule != "unmeasured" {
		t.Errorf("verdict = %+v", v)
	}
}

func TestExecWithSQLIsNamed(t *testing.T) {
	a := normalize.Action{Verb: "create", Resource: "pods", Subresource: "exec"}
	i := engine.Unmeasured("x")
	i.SQLDetected = true
	if v := eval(t, Default(), a, i, nil); v.Decision != Hold || v.Rule != "exec-with-sql" {
		t.Errorf("verdict = %+v", v)
	}
}

func TestUnknownLabelsHoldLabelRules(t *testing.T) {
	i := engine.Impact{Class: engine.ClassReversible, Measured: true, EndpointsLeft: map[string]int{"web": 0}}
	v := eval(t, Default(), del, i, nil)
	if v.Decision != Hold || v.Rule != "error:leaves-a-service-empty-in-prod" {
		t.Errorf("verdict = %+v", v)
	}
}

func TestUnknownLabelsDoNotAffectOtherRules(t *testing.T) {
	v := eval(t, Default(), del, engine.Impact{Class: engine.ClassReversible, Measured: true}, nil)
	if v.Decision != Allow || v.Rule != "safe" {
		t.Errorf("verdict = %+v", v)
	}
}

func TestMissingKeyIsAnErrorHold(t *testing.T) {
	p, err := Load([]byte(`
rules:
  - name: prod-only
    when: ns.labels.env == "prod"
    then: allow
default: allow
unmeasured: hold
`))
	if err != nil {
		t.Fatal(err)
	}
	v := eval(t, p, del, engine.Impact{Class: engine.ClassRead, Measured: true}, map[string]string{})
	if v.Decision != Hold || v.Rule != "error:prod-only" {
		t.Errorf("a rule that errored did not fail closed: %+v", v)
	}
}

func TestLoadRefusesBadPolicies(t *testing.T) {
	for name, doc := range map[string]string{
		"syntax":                         "rules:\n  - name: x\n    when: 'impact.class =='\n    then: hold\ndefault: hold\nunmeasured: hold\n",
		"not bool":                       "rules:\n  - name: x\n    when: impact.dataDestroyed\n    then: hold\ndefault: hold\nunmeasured: hold\n",
		"bad decision":                   "rules:\n  - name: x\n    when: 'true'\n    then: maybe\ndefault: hold\nunmeasured: hold\n",
		"bad name":                       "rules:\n  - name: 'Has Space'\n    when: 'true'\n    then: hold\ndefault: hold\nunmeasured: hold\n",
		"dup name":                       "rules:\n  - name: x\n    when: 'true'\n    then: hold\n  - name: x\n    when: 'true'\n    then: hold\ndefault: hold\nunmeasured: hold\n",
		"no default":                     "rules: []\nunmeasured: hold\n",
		"unknown var":                    "rules:\n  - name: x\n    when: request.user == \"a\"\n    then: hold\ndefault: hold\nunmeasured: hold\n",
		"unknown key":                    "rulez: []\ndefault: hold\nunmeasured: hold\n",
		"duplicate top-level rules key":  "rules: []\nrules:\n  - name: sneaky\n    when: 'true'\n    then: allow\ndefault: hold\nunmeasured: hold\n",
		"duplicate key in a rule":        "rules:\n  - name: x\n    when: 'false'\n    when: 'true'\n    then: allow\ndefault: hold\nunmeasured: hold\n",
		"case-insensitive top-level key": "Rules:\n  - name: x\n    when: 'true'\n    then: allow\nDEFAULT: hold\nunmeasured: hold\n",
		"multi-document":                 "rules: []\ndefault: hold\nunmeasured: hold\n---\nrules:\n  - name: sneaky\n    when: 'true'\n    then: allow\ndefault: allow\nunmeasured: allow\n",
		"unmeasured allow":               "rules: []\ndefault: hold\nunmeasured: allow\n",
	} {
		if _, err := Load([]byte(doc)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestAnAllowRuleCannotAllowUnmeasured(t *testing.T) {
	p, err := Load([]byte(`
rules:
  - name: allow-deletes
    when: action.verb == "delete"
    then: allow
default: hold
unmeasured: hold
`))
	if err != nil {
		t.Fatal(err)
	}
	v := eval(t, p, del, engine.Unmeasured("x"), nil)
	if v.Decision != Hold || v.Rule != "unmeasured" {
		t.Errorf("an allow rule allowed an unmeasured impact: %+v", v)
	}
}

func TestUnmeasuredAllowIsRefusedAtLoad(t *testing.T) {
	if _, err := Load([]byte("rules: []\ndefault: hold\nunmeasured: allow\n")); err == nil {
		t.Error("loaded a policy with unmeasured: allow")
	}
}

func TestADenyRuleDecidesDeny(t *testing.T) {
	p, err := Load([]byte(`
rules:
  - name: blocked
    when: action.verb == "delete"
    then: deny
default: hold
unmeasured: hold
`))
	if err != nil {
		t.Fatal(err)
	}
	v := eval(t, p, del, engine.Impact{Class: engine.ClassReversible, Measured: true}, nil)
	if v.Decision != Deny || v.Rule != "blocked" {
		t.Errorf("verdict = %+v", v)
	}
}

func TestDefaultDenyDecidesDeny(t *testing.T) {
	p, err := Load([]byte("rules: []\ndefault: deny\nunmeasured: hold\n"))
	if err != nil {
		t.Fatal(err)
	}
	v := eval(t, p, del, engine.Impact{Class: engine.ClassReversible, Measured: true}, nil)
	if v.Decision != Deny || v.Rule != "default" {
		t.Errorf("verdict = %+v", v)
	}
}

// A cancelled context must stop a rule mid-evaluation instead of letting a
// comprehension run to completion or to the cost limit, whichever comes
// first -- a proxy shedding load on a cancelled request must not wait for
// either.
func TestCancelledContextHolds(t *testing.T) {
	const nums = "[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19]"
	p, err := Load([]byte(`
rules:
  - name: loopy
    when: '` + nums + `.all(a, ` + nums + `.all(b, a+b >= 0))'
    then: allow
default: hold
unmeasured: hold
`))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v := p.Evaluate(ctx, del, engine.Impact{Class: engine.ClassReversible, Measured: true}, nil)
	if v.Decision != Hold || v.Rule != "error:loopy" {
		t.Errorf("a cancelled context did not hold: %+v", v)
	}
}

// A pathological expression must not hang the proxy.
func TestCostLimitHolds(t *testing.T) {
	p, err := Load([]byte(`
rules:
  - name: heavy
    when: '[1,2,3,4,5,6,7,8,9,10].all(a, [1,2,3,4,5,6,7,8,9,10].all(b, [1,2,3,4,5,6,7,8,9,10].all(c, [1,2,3,4,5,6,7,8,9,10].all(d, a+b+c+d > 0))))'
    then: allow
default: allow
unmeasured: hold
`))
	if err != nil {
		t.Fatal(err)
	}
	v := eval(t, p, del, engine.Impact{Class: engine.ClassRead, Measured: true}, nil)
	if v.Decision != Hold || v.Rule != "error:heavy" {
		t.Errorf("verdict = %+v", v)
	}
}

// The policy view shows DefaultText as what is in force when no file is
// set; it must be the very text Default parsed, and a copy.
func TestDefaultTextIsTheEmbeddedDefault(t *testing.T) {
	b := DefaultText()
	if _, err := Load(b); err != nil || len(b) == 0 {
		t.Fatalf("DefaultText does not load: %v", err)
	}
	if string(b) != string(defaultYAML) {
		t.Error("DefaultText differs from the embedded default")
	}
	b[0] ^= 0xff
	if string(DefaultText()) != string(defaultYAML) {
		t.Error("editing the returned text changed the embedded default")
	}
}
