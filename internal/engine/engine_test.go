package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/SaiPisey2/sounding/pkg/disruption"
	"github.com/SaiPisey2/sounding/pkg/model"
	"github.com/SaiPisey2/sounding/pkg/score"

	"github.com/SaiPisey2/blastgate/internal/normalize"
)

func finding(class model.Class, effects ...model.Effect) model.Finding {
	return model.NewFinding(model.Action{Verb: "delete"}, effects, class)
}

func eff(kind, objKind, name string) model.Effect {
	return model.Effect{Kind: kind, Object: model.Target{Kind: objKind, Name: name, Namespace: "demo"}, Basis: model.BasisComputed}
}

func TestFromFindingCountsDataAndClass(t *testing.T) {
	f := finding(model.ClassTerminal,
		eff("destroys", "PersistentVolumeClaim", "data"),
		eff("destroys-data", "PersistentVolume", "pv-1"),
		eff("destroys", "Pod", "web-1"))
	i := fromFinding(f, disruption.Report{})
	if i.Class != ClassTerminal || !i.Measured || i.DataDestroyed != 1 || len(i.Effects) != 3 || i.Undo != "objects" {
		t.Errorf("impact = %+v", i)
	}
}

func TestFromFindingCarriesDisruption(t *testing.T) {
	r := disruption.Report{
		Services: []disruption.Service{{Name: "web", Ready: 1, Left: 0}, {Name: "api", Ready: 2, Left: 2}},
		Budgets:  []disruption.Budget{{Name: "web-pdb", Healthy: 1, Desired: 1, Left: 0}},
	}
	i := fromFinding(finding(model.ClassReversible, eff("destroys", "Pod", "web-1")), r)
	if i.EndpointsLeft["web"] != 0 || i.EndpointsLeft["api"] != 2 {
		t.Errorf("endpoints = %v", i.EndpointsLeft)
	}
	if len(i.PDBViolations) != 1 || i.PDBViolations[0] != "web-pdb" {
		t.Errorf("pdb = %v", i.PDBViolations)
	}
}

func TestUnmeasuredIsTerminal(t *testing.T) {
	i := Unmeasured("why")
	if i.Measured || i.Class != ClassTerminal || i.Reason != "why" || i.Undo != "none" {
		t.Errorf("unmeasured = %+v", i)
	}
}

func TestDigestIgnoresElapsedAndOrder(t *testing.T) {
	a := Impact{Class: ClassTerminal, Measured: true, PDBViolations: []string{"b", "a"},
		Effects: []Effect{{"destroys", "Pod/demo/x", ""}, {"destroys", "Pod/demo/a", ""}}, Elapsed: time.Second}
	b := a
	b.Elapsed = 3 * time.Second
	b.PDBViolations = []string{"a", "b"}
	b.Effects = []Effect{{"destroys", "Pod/demo/a", ""}, {"destroys", "Pod/demo/x", ""}}
	if a.Digest() != b.Digest() {
		t.Error("elapsed time or ordering changed the digest")
	}
	c := a
	c.DataDestroyed = 1
	if a.Digest() == c.Digest() {
		t.Error("a real change did not change the digest")
	}
}

func TestSummaryHasNoObjectNames(t *testing.T) {
	i := Impact{Class: ClassTerminal, Measured: true, DataDestroyed: 2,
		EndpointsLeft: map[string]int{"secret-service-name": 0}, PDBViolations: []string{"pdb-name"},
		Effects: []Effect{{"destroys", "Pod/demo/web-1", ""}}}
	s := i.Summary()
	for _, leak := range []string{"secret-service-name", "pdb-name", "web-1", "demo"} {
		if strings.Contains(s, leak) {
			t.Errorf("summary %q names %q", s, leak)
		}
	}
	for _, want := range []string{"TERMINAL", "1 object", "2 volume", "1 service", "1 disruption budget"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary %q lacks %q", s, want)
		}
	}
}

// The score call is behind a seam so budget and refusal handling can be
// tested without a cluster.
func TestDeleteRefusedBySoundingIsUnmeasured(t *testing.T) {
	e := &Engine{budget: time.Second, scoreFn: func(context.Context, model.Action) (model.Finding, disruption.Report, error) {
		return model.Finding{}, disruption.Report{}, errors.Join(score.ErrRefused, errors.New("cluster-scoped"))
	}}
	i := e.assessDelete(context.Background(), actDelete("persistentvolumes", "", "pv-1"))
	if i.Measured || i.Class != ClassTerminal {
		t.Errorf("impact = %+v", i)
	}
}

func TestBudgetExceededIsUnmeasured(t *testing.T) {
	e := &Engine{budget: 50 * time.Millisecond, scoreFn: func(ctx context.Context, _ model.Action) (model.Finding, disruption.Report, error) {
		<-ctx.Done()
		return model.Finding{}, disruption.Report{}, ctx.Err()
	}}
	a := e.Assess(context.Background(), actDelete("pods", "demo", "web-1"), nil)
	if a.Impact.Measured || !strings.Contains(a.Impact.Reason, "budget") {
		t.Errorf("impact = %+v", a.Impact)
	}
}

func TestReadsAreNotScored(t *testing.T) {
	e := &Engine{budget: time.Second, scoreFn: func(context.Context, model.Action) (model.Finding, disruption.Report, error) {
		t.Fatal("a read was scored")
		return model.Finding{}, disruption.Report{}, nil
	}}
	a := actDelete("pods", "demo", "web-1")
	a.Verb = "get"
	if i := e.Assess(context.Background(), a, nil).Impact; i.Class != ClassRead || !i.Measured {
		t.Errorf("read impact = %+v", i)
	}
}

// `kubectl auth whoami` and `kubectl auth can-i` create a self-review:
// the API server answers a question about the caller and stores nothing.
// kubectl sends them as protobuf, which no dry-run can replay faithfully,
// so without this every whoami was held as unmeasured. Found live.
func TestSelfReviewsAreMeasuredReads(t *testing.T) {
	e := &Engine{budget: time.Second}
	for _, r := range []struct{ group, resource string }{
		{"authentication.k8s.io", "selfsubjectreviews"},
		{"authorization.k8s.io", "selfsubjectaccessreviews"},
		{"authorization.k8s.io", "selfsubjectrulesreviews"},
	} {
		a := normalize.Action{Verb: "create", Group: r.group, Version: "v1", Resource: r.resource, Principal: normalize.Principal{Human: "alice"}}
		if i := e.Assess(context.Background(), a, []byte{0x6b, 0x38, 0x73, 0x00}).Impact; i.Class != ClassRead || !i.Measured {
			t.Errorf("%s: impact = %+v", r.resource, i)
		}
	}
	// Anything else in those groups is still measured the ordinary way:
	// a review about someone else, or a verb other than create.
	for _, a := range []normalize.Action{
		{Verb: "create", Group: "authorization.k8s.io", Version: "v1", Resource: "subjectaccessreviews"},
		{Verb: "create", Group: "authorization.k8s.io", Version: "v1", Resource: "selfsubjectaccessreviews", Subresource: "status", Name: "x"},
		{Verb: "update", Group: "authentication.k8s.io", Version: "v1", Resource: "selfsubjectreviews", Name: "x"},
	} {
		if i := e.Assess(context.Background(), a, nil).Impact; i.Class == ClassRead {
			t.Errorf("%+v scored as a read", a)
		}
	}
}

func TestDeleteCollectionIsUnmeasured(t *testing.T) {
	e := &Engine{budget: time.Second}
	a := actDelete("pods", "demo", "")
	a.Verb = "deletecollection"
	if i := e.Assess(context.Background(), a, nil).Impact; i.Measured {
		t.Errorf("deletecollection measured: %+v", i)
	}
}

func actDelete(resource, ns, name string) normalize.Action {
	return normalize.Action{Verb: "delete", Version: "v1", Resource: resource, Namespace: ns, Name: name}
}

func noScore(t *testing.T) func(context.Context, model.Action) (model.Finding, disruption.Report, error) {
	return func(context.Context, model.Action) (model.Finding, disruption.Report, error) {
		t.Fatal("scored an action that must not be")
		return model.Finding{}, disruption.Report{}, nil
	}
}

// kubectl opens exec, attach and port-forward as a WebSocket GET; a GET
// must not reach the read case and pass an arbitrary command as READ.
func TestExecAttachPortforwardAreUnmeasuredForAnyVerb(t *testing.T) {
	e := &Engine{budget: time.Second, scoreFn: noScore(t)}
	for _, sub := range []string{"exec", "attach", "portforward"} {
		for _, verb := range []string{"get", "create"} {
			a := actDelete("pods", "demo", "web-1")
			a.Verb, a.Subresource = verb, sub
			if i := e.Assess(context.Background(), a, nil).Impact; i.Measured || i.Class != ClassTerminal {
				t.Errorf("%s pods/%s: %+v", verb, sub, i)
			}
		}
	}
}

func TestProxyIsUnmeasuredForAnyVerb(t *testing.T) {
	e := &Engine{budget: time.Second, scoreFn: noScore(t)}
	for _, res := range []string{"pods", "services", "nodes"} {
		for _, verb := range []string{"get", "create", "delete"} {
			a := actDelete(res, "demo", "x")
			a.Verb, a.Subresource = verb, "proxy"
			if i := e.Assess(context.Background(), a, nil).Impact; i.Measured || !strings.Contains(i.Reason, "proxied") {
				t.Errorf("%s %s/proxy: %+v", verb, res, i)
			}
		}
	}
}

func terminalScore(context.Context, model.Action) (model.Finding, disruption.Report, error) {
	return finding(model.ClassTerminal), disruption.Report{}, nil
}

func TestNamespaceDeleteLooksUpItsOwnName(t *testing.T) {
	var looked []string
	e := &Engine{budget: time.Second, scoreFn: terminalScore,
		labelsFn: func(ctx context.Context, ns string) (map[string]string, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Error("label lookup has no deadline")
			}
			looked = append(looked, ns)
			return map[string]string{"env": "prod"}, nil
		}}
	a := actDelete("namespaces", "", "payments")
	got := e.Assess(context.Background(), a, nil)
	if len(looked) != 1 || looked[0] != "payments" || got.NamespaceLabels["env"] != "prod" {
		t.Errorf("looked up %v, labels %v", looked, got.NamespaceLabels)
	}
}

func TestReadSkipsLabelLookup(t *testing.T) {
	e := &Engine{budget: time.Second, scoreFn: noScore(t),
		labelsFn: func(context.Context, string) (map[string]string, error) {
			t.Fatal("a read looked up namespace labels")
			return nil, nil
		}}
	a := actDelete("pods", "demo", "web-1")
	a.Verb = "get"
	if got := e.Assess(context.Background(), a, nil); got.NamespaceLabels != nil {
		t.Errorf("read labels = %v", got.NamespaceLabels)
	}
}

// A failed lookup must be nil (unknown), never an empty map that reads as
// "this namespace has no labels"; an empty map is only a namespace that
// was read and has none.
func TestLabelLookupFailureIsNilAndNoLabelsIsEmpty(t *testing.T) {
	e := &Engine{budget: time.Second, scoreFn: terminalScore,
		labelsFn: func(context.Context, string) (map[string]string, error) {
			return nil, errors.New("forbidden")
		}}
	if got := e.Assess(context.Background(), actDelete("pods", "demo", "web-1"), nil); got.NamespaceLabels != nil {
		t.Errorf("failed lookup labels = %#v, want nil", got.NamespaceLabels)
	}
	e.labelsFn = func(context.Context, string) (map[string]string, error) { return nil, nil }
	got := e.Assess(context.Background(), actDelete("pods", "demo", "web-1"), nil)
	if got.NamespaceLabels == nil || len(got.NamespaceLabels) != 0 {
		t.Errorf("unlabelled namespace labels = %#v, want empty non-nil", got.NamespaceLabels)
	}
}

func TestSummaryCountsUnknownDataFate(t *testing.T) {
	i := fromFinding(finding(model.ClassTerminal,
		eff("unknown-data-fate", "PersistentVolumeClaim", "data"),
		eff("unknown-data-fate", "PersistentVolume", "pv-2")), disruption.Report{})
	if s := i.Summary(); !strings.Contains(s, "2 volumes with unknown data fate") || strings.Contains(s, "pv-2") {
		t.Errorf("summary = %q", s)
	}
}

func TestFromFindingUnknownClassIsUnmeasured(t *testing.T) {
	i := fromFinding(finding(model.Class(99)), disruption.Report{})
	if i.Measured || i.Class != ClassTerminal {
		t.Errorf("impact = %+v", i)
	}
}

func TestEffectObjectCarriesGroup(t *testing.T) {
	d := eff("destroys", "Deployment", "web")
	d.Object.Group = "apps"
	i := fromFinding(finding(model.ClassReversible, d, eff("destroys", "Pod", "web-1")), disruption.Report{})
	if i.Effects[0].Object != "apps/Deployment/demo/web" || i.Effects[1].Object != "Pod/demo/web-1" {
		t.Errorf("objects = %q, %q", i.Effects[0].Object, i.Effects[1].Object)
	}
}

func TestDigestTieBreaksOnExplanation(t *testing.T) {
	a := Impact{Class: ClassTerminal, Measured: true,
		Effects: []Effect{{"destroys", "Pod/demo/x", "one"}, {"destroys", "Pod/demo/x", "two"}}}
	b := a
	b.Effects = []Effect{{"destroys", "Pod/demo/x", "two"}, {"destroys", "Pod/demo/x", "one"}}
	if a.Digest() != b.Digest() {
		t.Error("order of same-object same-kind effects changed the digest")
	}
}

// A scorer that ignores its context and comes back late with a measured
// answer must not be believed: parts of the measurement may be stale.
func TestMeasuredAfterDeadlineIsUnmeasured(t *testing.T) {
	e := &Engine{budget: 20 * time.Millisecond, scoreFn: func(context.Context, model.Action) (model.Finding, disruption.Report, error) {
		time.Sleep(100 * time.Millisecond)
		return finding(model.ClassReversible, eff("destroys", "Pod", "web-1")), disruption.Report{}, nil
	}}
	i := e.Assess(context.Background(), actDelete("pods", "demo", "web-1"), nil).Impact
	if i.Measured || i.Class != ClassTerminal || !strings.Contains(i.Reason, "budget") {
		t.Errorf("impact = %+v", i)
	}
}

func TestEvictionIsScoredAsDeleteOfThatPod(t *testing.T) {
	var got model.Action
	e := &Engine{budget: time.Second, scoreFn: func(_ context.Context, act model.Action) (model.Finding, disruption.Report, error) {
		got = act
		return finding(model.ClassReversible, eff("destroys", "Pod", "web-1")), disruption.Report{}, nil
	}}
	a := actDelete("pods", "demo", "web-1")
	a.Verb, a.Subresource = "create", "eviction"
	i := e.Assess(context.Background(), a, nil).Impact
	want := model.Target{Version: "v1", Resource: "pods", Namespace: "demo", Name: "web-1"}
	if got.Verb != "delete" || got.Target != want || !i.Measured || i.Class != ClassReversible {
		t.Errorf("scored %+v, impact %+v", got, i)
	}
}
