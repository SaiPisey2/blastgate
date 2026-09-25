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
	if v := eval(t, Default(), a, i, nil); v.Rule != "exec-with-sql" {
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
unmeasured: allow
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
		"syntax":       "rules:\n  - name: x\n    when: 'impact.class =='\n    then: hold\ndefault: hold\nunmeasured: hold\n",
		"not bool":     "rules:\n  - name: x\n    when: impact.dataDestroyed\n    then: hold\ndefault: hold\nunmeasured: hold\n",
		"bad decision": "rules:\n  - name: x\n    when: 'true'\n    then: maybe\ndefault: hold\nunmeasured: hold\n",
		"bad name":     "rules:\n  - name: 'Has Space'\n    when: 'true'\n    then: hold\ndefault: hold\nunmeasured: hold\n",
		"dup name":     "rules:\n  - name: x\n    when: 'true'\n    then: hold\n  - name: x\n    when: 'true'\n    then: hold\ndefault: hold\nunmeasured: hold\n",
		"no default":   "rules: []\nunmeasured: hold\n",
		"unknown var":  "rules:\n  - name: x\n    when: request.user == \"a\"\n    then: hold\ndefault: hold\nunmeasured: hold\n",
		"unknown key":  "rulez: []\ndefault: hold\nunmeasured: hold\n",
	} {
		if _, err := Load([]byte(doc)); err == nil {
			t.Errorf("%s: loaded", name)
		}
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
unmeasured: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	v := eval(t, p, del, engine.Impact{Class: engine.ClassRead, Measured: true}, nil)
	if v.Decision != Hold || v.Rule != "error:heavy" {
		t.Errorf("verdict = %+v", v)
	}
}
