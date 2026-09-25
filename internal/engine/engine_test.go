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
