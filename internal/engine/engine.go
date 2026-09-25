package engine

import (
	"context"
	"errors"
	"net/http"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/SaiPisey2/sounding/pkg/cluster"
	"github.com/SaiPisey2/sounding/pkg/disruption"
	"github.com/SaiPisey2/sounding/pkg/model"

	"github.com/SaiPisey2/blastgate/internal/normalize"
	"github.com/SaiPisey2/blastgate/internal/upstream"
)

type Assessment struct {
	Impact          Impact
	NamespaceLabels map[string]string
}

type Engine struct {
	up     *upstream.Upstream
	budget time.Duration
	// scoreFn is sounding's delete scoring plus disruption for the pods it
	// removes. A field so unit tests can drive budget and refusal handling
	// without a cluster.
	scoreFn func(context.Context, model.Action) (model.Finding, disruption.Report, error)
	// httpDo sends an impersonated request to the API server (dry-runs and
	// "before" reads). A field for the same reason.
	httpDo func(*http.Request) (*http.Response, error)
}

func New(up *upstream.Upstream, budget time.Duration) *Engine {
	e := &Engine{up: up, budget: budget}
	e.scoreFn = e.soundingScore
	e.httpDo = func(r *http.Request) (*http.Response, error) { return up.Normal.RoundTrip(r) }
	return e
}

// Assess scores a within the time budget. It never fails: anything it
// cannot measure -- a refusal, an error, the budget running out -- comes
// back as Unmeasured, which policy holds.
func (e *Engine) Assess(ctx context.Context, a normalize.Action, body []byte) Assessment {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, e.budget)
	defer cancel()
	var i Impact
	switch {
	case a.IsRead():
		i = Impact{Class: ClassRead, Measured: true, Undo: "none"}
	case a.Verb == "delete" && a.Subresource == "":
		i = e.assessDelete(ctx, a)
	case a.Resource == "pods" && a.Subresource == "eviction" && a.Verb == "create":
		// An eviction removes the pod, respecting budgets; it is scored as
		// deleting that pod.
		d := a
		d.Verb, d.Subresource = "delete", ""
		i = e.assessDelete(ctx, d)
	case a.Resource == "pods" && (a.Subresource == "exec" || a.Subresource == "attach" || a.Subresource == "portforward"):
		i = assessExec(a)
	case a.Verb == "create" || a.Verb == "update" || a.Verb == "patch":
		i = e.assessMutation(ctx, a, body)
	default:
		i = Unmeasured("verb " + a.Verb + " is not measured by this build")
	}
	if ctx.Err() != nil && i.Measured {
		// A measurement that finished after the deadline is not trusted: parts
		// of it may have been cut short.
		i = Unmeasured("scoring exceeded the time budget")
	} else if errors.Is(ctx.Err(), context.DeadlineExceeded) && !i.Measured {
		i.Reason = "scoring exceeded the time budget"
	}
	i.Elapsed = time.Since(start)
	return Assessment{Impact: i, NamespaceLabels: e.namespaceLabels(a.Namespace)}
}

// clients builds sounding's read-only clients from the service account's
// config. One per call: sounding's Clients is not safe for concurrent
// scoring, and the proxy scores concurrent requests.
func (e *Engine) clients() (*cluster.Clients, error) {
	if e.up == nil || e.up.Config == nil {
		// NewForConfig copies the config first and panics on nil; an error
		// here becomes Unmeasured, a panic would kill the request unheld.
		return nil, errors.New("no upstream config to score with")
	}
	return cluster.NewForConfig(e.up.Config)
}

func (e *Engine) namespaceLabels(ns string) map[string]string {
	if ns == "" || e.up == nil || e.up.Config == nil {
		return map[string]string{}
	}
	c, err := e.clients()
	if err != nil {
		return map[string]string{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	n, err := c.Typed.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	if err != nil || n.Labels == nil {
		// Missing labels are an empty map, not an error: the default policy
		// tests membership with "in", and a lookup failure must not make an
		// ordinary namespace look like production or like anything else.
		return map[string]string{}
	}
	return n.Labels
}
