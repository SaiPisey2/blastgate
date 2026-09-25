package engine

import (
	"context"
	"fmt"

	"github.com/SaiPisey2/sounding/pkg/disruption"
	"github.com/SaiPisey2/sounding/pkg/model"
	"github.com/SaiPisey2/sounding/pkg/score"

	"github.com/SaiPisey2/blastgate/internal/normalize"
)

func (e *Engine) assessDelete(ctx context.Context, a normalize.Action) Impact {
	f, r, err := e.scoreFn(ctx, model.Action{Verb: "delete", Target: model.Target{
		Group: a.Group, Version: a.Version, Resource: a.Resource, Namespace: a.Namespace, Name: a.Name,
	}})
	if err != nil {
		// sounding refuses what it cannot score exactly (a cluster-scoped
		// resource, an ambiguous name, incomplete discovery) rather than
		// report something smaller. That is unmeasured here, never safe.
		return Unmeasured(fmt.Sprintf("delete not measured: %v", err))
	}
	return fromFinding(f, r)
}

// soundingScore is the production scoreFn.
func (e *Engine) soundingScore(ctx context.Context, act model.Action) (model.Finding, disruption.Report, error) {
	c, err := e.clients()
	if err != nil {
		return model.Finding{}, disruption.Report{}, err
	}
	f, err := score.Score(ctx, c, act, score.Options{})
	if err != nil {
		return model.Finding{}, disruption.Report{}, err
	}
	var pods []string
	ns := act.Target.Namespace
	for _, ef := range f.Effects {
		if ef.Kind == "destroys" && ef.Object.Resource == "pods" && ef.Object.Group == "" {
			pods = append(pods, ef.Object.Name)
			ns = ef.Object.Namespace
		}
	}
	if len(pods) == 0 || ns == "" {
		return f, disruption.Report{}, nil
	}
	r, err := disruption.Assess(ctx, c, ns, disruption.Removal{Pods: pods})
	if err != nil {
		return model.Finding{}, disruption.Report{}, err
	}
	return f, r, nil
}

func fromFinding(f model.Finding, r disruption.Report) Impact {
	switch f.Class {
	case model.ClassRead, model.ClassReversible, model.ClassCompensable, model.ClassTerminal, model.ClassAuthority:
	default:
		// A class this build does not know (a newer sounding) would reach
		// policy as a string no rule matches. Unmeasured holds it instead.
		return Unmeasured(fmt.Sprintf("sounding returned an unknown class %d", int(f.Class)))
	}
	i := Impact{Class: f.Class.String(), Measured: true, Undo: "objects"}
	for _, ef := range f.Effects {
		if ef.Kind == "destroys-data" {
			i.DataDestroyed++
		}
		i.Effects = append(i.Effects, Effect{
			Kind:        ef.Kind,
			Object:      objectRef(ef.Object),
			Explanation: ef.Explanation,
		})
	}
	if len(r.Services) > 0 {
		i.EndpointsLeft = map[string]int{}
		for _, s := range r.Services {
			i.EndpointsLeft[s.Name] = s.Left
		}
	}
	i.PDBViolations = r.Violated()
	return i
}

// objectRef names an effect's object. The group is part of it because two
// kinds of the same name in different groups (a CRD shadowing a built-in)
// are different objects, and the digest must tell them apart.
func objectRef(t model.Target) string {
	ref := t.Kind + "/" + t.Namespace + "/" + t.Name
	if t.Group != "" {
		ref = t.Group + "/" + ref
	}
	return ref
}
