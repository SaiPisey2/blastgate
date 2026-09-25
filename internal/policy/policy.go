// Package policy decides allow, hold or deny from an action and its
// measured impact (design §3.4), in CEL -- Kubernetes' own policy
// language. It fails closed: a rule that cannot be evaluated holds, a
// policy that does not compile (or that does not compile to exactly the
// shape this package expects) is refused at load, never half-applied, and
// an unmeasured impact can never be allowed, however a policy is written.
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
//	           ns.labels is present only when the namespace lookup
//	           succeeded (engine.Assessment.NamespaceLabels != nil); an
//	           empty-but-known namespace still has ns.labels (as {}). When
//	           the lookup failed, ns has no "labels" key at all, so a rule
//	           that reads ns.labels AND whose result actually depends on
//	           that read fails to evaluate and holds -- fail closed on
//	           what could not be looked up, not just on what was measured.
//	           CEL's && and || absorb an error from one side when the
//	           other side alone already determines the result (e.g. `false
//	           && ns.labels.env == "prod"` evaluates to false without
//	           error, whichever side CEL evaluates first), so a rule that
//	           only reads ns.labels behind such a guard is unaffected when
//	           the guard alone is false: see leaves-a-service-empty-in-prod
//	           in default.yaml.
//
// Every field a variable exposes is typed dyn (its static type is decided
// at runtime, not at compile time), because the underlying Go maps are
// heterogeneous. A `when` that merely selects a dyn field -- e.g.
// `impact.measured` alone, with no comparison -- has no exact static bool
// type either, and Load refuses it; write `impact.measured == true`.
//
// Rules are evaluated in order and the first whose `when` is true decides
// (see Evaluate); an error partway through stops there. A rule that
// itself fails to evaluate turns not just its own decision but every rule
// after it, deny included, into a hold -- put deny rules before rules more
// likely to error on some inputs.
package policy

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"regexp"

	"github.com/google/cel-go/cel"
	goyaml "go.yaml.in/yaml/v2"
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

// interruptCheckFrequency is how often, in comprehension iterations, a
// running rule notices its context was cancelled. Without it a rule with
// a loop (an `all`/`exists` over a list or map) ignores cancellation
// entirely and runs to completion or to the cost limit, whichever first;
// a proxy shedding load on a cancelled request must not wait for either.
const interruptCheckFrequency = 100

type ruleDoc struct {
	Name string `json:"name"`
	When string `json:"when"`
	Then string `json:"then"`
}

type doc struct {
	Rules      []ruleDoc
	Default    string
	Unmeasured string
}

// topLevelKeys and ruleKeys are the only keys Load accepts, checked before
// any typed decode. encoding/json's own field matching falls back to a
// case-insensitive match on a struct's JSON tag when there is no exact
// one, so decoding straight into a struct would silently bind "Rules" or
// "DEFAULT" to the field a lowercase key means -- exactly the kind of
// policy that looks refused-if-misspelled but is not.
var topLevelKeys = map[string]bool{"rules": true, "default": true, "unmeasured": true}
var ruleKeys = map[string]bool{"name": true, "when": true, "then": true}

func Default() *Policy {
	p, err := Load(defaultYAML)
	if err != nil {
		panic("embedded default policy is invalid: " + err.Error())
	}
	return p
}

func Load(data []byte) (*Policy, error) {
	if multiDocument(data) {
		// YAMLToJSONStrict below reads only the first document, silently:
		// anything after the first "---" would never be checked, however
		// dangerous, and never take effect either -- neither is safe to
		// let through quietly.
		return nil, fmt.Errorf("policy: only one YAML document is allowed")
	}
	// Strict: a key repeated at any level (a second top-level `rules:`, a
	// second `when:` inside one rule) is refused instead of the last one
	// silently winning -- YAMLToJSON alone picks one in an undefined
	// order and drops the rest.
	js, err := yaml.YAMLToJSONStrict(data)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	d, err := parseDoc(js)
	if err != nil {
		return nil, err
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
	// unmeasured can never be allow: an impact this build could not
	// measure is the one case global-constraints names outright, and no
	// policy, however written, may override it.
	if p.unmea, err = decision(d.Unmeasured, "unmeasured"); err != nil {
		return nil, err
	}
	if p.unmea == Allow {
		return nil, fmt.Errorf("policy: unmeasured must be hold or deny, not allow -- an unmeasured impact can never be allowed")
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
		prg, err := env.Program(ast, cel.CostLimit(costLimit), cel.InterruptCheckFrequency(interruptCheckFrequency))
		if err != nil {
			return nil, fmt.Errorf("policy: rule %q: %w", r.Name, err)
		}
		p.rules = append(p.rules, rule{name: r.Name, then: then, prg: prg})
	}
	return p, nil
}

// multiDocument reports whether data holds more than one YAML document
// (documents separated by a "---" line). go.yaml.in/yaml/v2 is the same
// library sigs.k8s.io/yaml itself uses to implement YAMLToJSON, so this
// parses documents exactly as that conversion does.
func multiDocument(data []byte) bool {
	dec := goyaml.NewDecoder(bytes.NewReader(data))
	var first any
	if err := dec.Decode(&first); err != nil {
		return false // a real syntax error is reported by YAMLToJSONStrict below
	}
	var second any
	return dec.Decode(&second) != io.EOF
}

// parseDoc decodes js (produced by YAMLToJSONStrict) into a doc, refusing
// any key at the top level or inside a rule that is not exactly one this
// package understands -- see topLevelKeys and ruleKeys.
func parseDoc(js []byte) (doc, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(js, &top); err != nil {
		return doc{}, fmt.Errorf("policy: %w", err)
	}
	if err := exactKeys(top, topLevelKeys, "policy"); err != nil {
		return doc{}, err
	}
	var d doc
	if raw, ok := top["default"]; ok {
		if err := json.Unmarshal(raw, &d.Default); err != nil {
			return doc{}, fmt.Errorf("policy: default: %w", err)
		}
	}
	if raw, ok := top["unmeasured"]; ok {
		if err := json.Unmarshal(raw, &d.Unmeasured); err != nil {
			return doc{}, fmt.Errorf("policy: unmeasured: %w", err)
		}
	}
	raw, ok := top["rules"]
	if !ok {
		return d, nil
	}
	var rawRules []json.RawMessage
	if err := json.Unmarshal(raw, &rawRules); err != nil {
		return doc{}, fmt.Errorf("policy: rules: %w", err)
	}
	for _, rr := range rawRules {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(rr, &fields); err != nil {
			return doc{}, fmt.Errorf("policy: rule: %w", err)
		}
		if err := exactKeys(fields, ruleKeys, "rule"); err != nil {
			return doc{}, err
		}
		var r ruleDoc
		if err := json.Unmarshal(rr, &r); err != nil {
			return doc{}, fmt.Errorf("policy: rule: %w", err)
		}
		d.Rules = append(d.Rules, r)
	}
	return d, nil
}

func exactKeys(m map[string]json.RawMessage, allowed map[string]bool, where string) error {
	for k := range m {
		if !allowed[k] {
			return fmt.Errorf("policy: %s has an unknown key %q", where, k)
		}
	}
	return nil
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
			if r.then == Allow && !i.Measured {
				// A rule can only reach this far by matching on something
				// other than measuredness (impact.class, action.verb, ...);
				// global-constraints is unconditional here, so allow is
				// downgraded exactly like the policy-level unmeasured
				// setting Load already refuses to let be allow.
				return Verdict{Decision: Hold, Rule: "unmeasured"}
			}
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
	v := map[string]any{"name": ns}
	// labels == nil means the lookup failed and the namespace's labels are
	// unknown, not that it has none (that is labels == map[string]string{}).
	// Omitting the "labels" key entirely -- rather than substituting an
	// empty map -- makes ns.labels a missing-key evaluation error, which
	// Evaluate turns into a hold; a rule that never reads ns.labels is
	// untouched.
	if labels != nil {
		l := map[string]any{}
		for k, val := range labels {
			l[k] = val
		}
		v["labels"] = l
	}
	return v
}
