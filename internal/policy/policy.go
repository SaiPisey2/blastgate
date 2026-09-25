// Package policy decides allow, hold or deny from an action and its
// measured impact (design §3.4), in CEL -- Kubernetes' own policy
// language. It fails closed: a rule that cannot be evaluated holds, and a
// policy that does not compile is refused at load, never half-applied.
//
// A rule's `when` expression sees three variables, built exactly as below:
//
//	action:    verb, group, version, resource, subresource, namespace,
//	           name, source, agent, human
//	impact:    class, measured, reason, objects, dataDestroyed,
//	           endpointsLeft (map[string]int), pdbViolations ([]string),
//	           sqlDetected, dryRunRejected, undo
//	ns:        name, labels (map[string]string) -- the object's own
//	           namespace field is called "namespace"; the top-level CEL
//	           variable is called "ns" because cel-go v0.29.2 reserves
//	           "namespace" as an identifier (it is valid as a proto field
//	           name but not as a variable), and refuses to compile any
//	           rule that declares or references it directly.
package policy

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/google/cel-go/cel"
	"sigs.k8s.io/yaml"

	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/normalize"
)

type Decision string

const (
	Allow Decision = "allow"
	Hold  Decision = "hold"
	Deny  Decision = "deny"
)

type Verdict struct {
	Decision Decision
	Rule     string
}

type rule struct {
	name string
	then Decision
	prg  cel.Program
}

type Policy struct {
	rules      []rule
	def, unmea Decision
}

//go:embed default.yaml
var defaultYAML []byte

// ruleName is also the shape rule names must have to appear in a client
// message (the ticket names the rule that held the request).
var ruleName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// costLimit bounds one rule's evaluation. A policy is operator-written,
// but a mistake in one must not stall every request behind it.
const costLimit = 100000

type doc struct {
	Rules []struct {
		Name string `json:"name"`
		When string `json:"when"`
		Then string `json:"then"`
	} `json:"rules"`
	Default    string `json:"default"`
	Unmeasured string `json:"unmeasured"`
}

func Default() *Policy {
	p, err := Load(defaultYAML)
	if err != nil {
		panic("embedded default policy is invalid: " + err.Error())
	}
	return p
}

func Load(data []byte) (*Policy, error) {
	js, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	var d doc
	dec := json.NewDecoder(bytes.NewReader(js))
	dec.DisallowUnknownFields() // a typo'd key must not silently drop rules
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	env, err := cel.NewEnv(
		cel.Variable("action", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("impact", cel.MapType(cel.StringType, cel.DynType)),
		// "namespace" itself cannot be declared: cel-go reserves it as a
		// parser keyword (see the package comment).
		cel.Variable("ns", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, err
	}
	p := &Policy{}
	if p.def, err = decision(d.Default, "default"); err != nil {
		return nil, err
	}
	if p.unmea, err = decision(d.Unmeasured, "unmeasured"); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, r := range d.Rules {
		if !ruleName.MatchString(r.Name) || r.Name == "default" || r.Name == "unmeasured" {
			return nil, fmt.Errorf("policy: rule name %q must be lowercase letters, digits and dashes", r.Name)
		}
		if seen[r.Name] {
			return nil, fmt.Errorf("policy: rule %q defined twice", r.Name)
		}
		seen[r.Name] = true
		then, err := decision(r.Then, r.Name)
		if err != nil {
			return nil, err
		}
		ast, iss := env.Compile(r.When)
		if iss.Err() != nil {
			return nil, fmt.Errorf("policy: rule %q: %w", r.Name, iss.Err())
		}
		if !ast.OutputType().IsExactType(cel.BoolType) {
			return nil, fmt.Errorf("policy: rule %q must evaluate to a bool, not %s", r.Name, ast.OutputType())
		}
		prg, err := env.Program(ast, cel.CostLimit(costLimit))
		if err != nil {
			return nil, fmt.Errorf("policy: rule %q: %w", r.Name, err)
		}
		p.rules = append(p.rules, rule{name: r.Name, then: then, prg: prg})
	}
	return p, nil
}

func decision(s, where string) (Decision, error) {
	switch Decision(s) {
	case Allow, Hold, Deny:
		return Decision(s), nil
	}
	return "", fmt.Errorf("policy: %s must be allow, hold or deny, not %q", where, s)
}

func (p *Policy) Evaluate(ctx context.Context, a normalize.Action, i engine.Impact, nsLabels map[string]string) Verdict {
	vars := map[string]any{"action": actionVars(a), "impact": impactVars(i), "ns": namespaceVars(a.Namespace, nsLabels)}
	for _, r := range p.rules {
		out, _, err := r.prg.ContextEval(ctx, vars)
		if err != nil {
			return Verdict{Decision: Hold, Rule: "error:" + r.name}
		}
		b, ok := out.Value().(bool)
		if !ok {
			return Verdict{Decision: Hold, Rule: "error:" + r.name}
		}
		if b {
			return Verdict{Decision: r.then, Rule: r.name}
		}
	}
	if !i.Measured {
		return Verdict{Decision: p.unmea, Rule: "unmeasured"}
	}
	return Verdict{Decision: p.def, Rule: "default"}
}

func actionVars(a normalize.Action) map[string]any {
	return map[string]any{"verb": a.Verb, "group": a.Group, "version": a.Version, "resource": a.Resource,
		"subresource": a.Subresource, "namespace": a.Namespace, "name": a.Name, "source": a.Source,
		"agent": a.Principal.Agent, "human": a.Principal.Human}
}

func impactVars(i engine.Impact) map[string]any {
	ep := map[string]any{}
	for k, v := range i.EndpointsLeft {
		ep[k] = int64(v)
	}
	pdb := make([]any, 0, len(i.PDBViolations))
	for _, v := range i.PDBViolations {
		pdb = append(pdb, v)
	}
	return map[string]any{"class": i.Class, "measured": i.Measured, "reason": i.Reason,
		"objects": int64(len(i.Effects)), "dataDestroyed": int64(i.DataDestroyed), "endpointsLeft": ep,
		"pdbViolations": pdb, "sqlDetected": i.SQLDetected, "dryRunRejected": i.DryRunRejected, "undo": i.Undo}
}

func namespaceVars(ns string, labels map[string]string) map[string]any {
	l := map[string]any{}
	for k, v := range labels {
		l[k] = v
	}
	return map[string]any{"name": ns, "labels": l}
}
