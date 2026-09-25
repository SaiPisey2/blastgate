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

// Assessment is an action's impact plus the labels of the namespace it
// touches, which policy reads.
//
// NamespaceLabels is nil when the labels are unknown: the lookup failed
// (client, RBAC, timeout, not found), there is no namespace to look up, or
// the action is a read and is never evaluated. Policy must hold a rule that
// reads labels it does not have, because a failed lookup that looked like
// "no labels" would let a production namespace pass as an ordinary one.
// An empty, non-nil map means the namespace was read and has no labels.
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
	// labelsFn reads a namespace's labels. A field so tests can see which
	// namespace is looked up, and whether one is, without a cluster.
	labelsFn func(ctx context.Context, ns string) (map[string]string, error)
	// look lists the Services and Pods a relabel or retarget affects and
	// measures a scale-down's disruption. A field so tests can supply them.
	look lookups
}

func New(up *upstream.Upstream, budget time.Duration) *Engine {
	e := &Engine{up: up, budget: budget}
	e.scoreFn = e.soundingScore
	e.labelsFn = e.readNamespaceLabels
	if up != nil {
		e.look = soundingLookups{cfg: up.Config}
	} else {
		e.look = soundingLookups{}
	}
	e.httpDo = func(r *http.Request) (*http.Response, error) { return up.Normal.RoundTrip(r) }
	return e
}

// Assess scores a within the time budget. It never fails: anything it
// cannot measure -- a refusal, an error, the budget running out -- comes
// back as Unmeasured, which policy holds.
func (e *Engine) Assess(parent context.Context, a normalize.Action, body []byte) Assessment {
	start := time.Now()
	ctx, cancel := context.WithTimeout(parent, e.budget)
	defer cancel()
	var i Impact
	switch {
	// The two cases below come before the read case on purpose: kubectl
	// opens exec, attach and port-forward as a WebSocket GET, which
	// normalises to verb "get", and a proxied GET can reach anything the
	// pod or service serves. Letting IsRead see them first would pass an
	// arbitrary command through as a measured READ.
	case a.Subresource == "proxy":
		i = Unmeasured("a proxied request cannot be measured")
	case a.Resource == "pods" && (a.Subresource == "exec" || a.Subresource == "attach" || a.Subresource == "portforward"):
		i = assessExec(a)
	case a.Resource == "pods" && a.Group == "" && a.Subresource == "ephemeralcontainers" && !a.IsRead():
		// `kubectl debug` starts a container with a command of its choosing
		// by patching this subresource. The dry-run would call that a
		// REVERSIBLE change to the Pod, and the safe rule would let the
		// command run unheld; like exec, it cannot be measured.
		i = assessEphemeral(a, body)
	case a.IsRead(), isSelfReview(a):
		i = Impact{Class: ClassRead, Measured: true, Undo: "none"}
	case a.Verb == "delete" && a.Subresource == "":
		i = e.assessDelete(ctx, a)
	case a.Resource == "pods" && a.Subresource == "eviction" && a.Verb == "create":
		// An eviction removes the pod, respecting budgets; it is scored as
		// deleting that pod.
		d := a
		d.Verb, d.Subresource = "delete", ""
		i = e.assessDelete(ctx, d)
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
	if i.Class == ClassRead {
		// Reads are never evaluated by policy, so their labels are not worth
		// a request to the API server.
		return Assessment{Impact: i}
	}
	return Assessment{Impact: i, NamespaceLabels: e.namespaceLabels(parent, a)}
}

// isSelfReview reports the creates that only ask the API server about the
// caller -- `kubectl auth whoami` and `kubectl auth can-i` -- and store
// nothing. kubectl sends them as protobuf, which the dry-run cannot replay
// faithfully, so measuring them as mutations held every whoami. A review
// about someone else (subjectaccessreviews, tokenreviews) is not one: it
// needs its own grant and discloses another's rights, so it stays a write.
func isSelfReview(a normalize.Action) bool {
	if a.Verb != "create" || a.Subresource != "" || a.Name != "" {
		return false
	}
	switch a.Group {
	case "authentication.k8s.io":
		return a.Resource == "selfsubjectreviews"
	case "authorization.k8s.io":
		return a.Resource == "selfsubjectaccessreviews" || a.Resource == "selfsubjectrulesreviews"
	}
	return false
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

// namespaceLabels returns the labels of the namespace a touches, or nil
// when they are unknown (see Assessment).
func (e *Engine) namespaceLabels(parent context.Context, a normalize.Action) map[string]string {
	ns := a.Namespace
	if a.Resource == "namespaces" && a.Group == "" && a.Subresource == "" {
		// A namespace is cluster-scoped: its own name is the namespace whose
		// labels matter. Without this, deleting a production namespace would
		// be evaluated with no labels at all.
		ns = a.Name
	}
	if ns == "" || e.labelsFn == nil {
		return nil
	}
	// Bounded by the caller's context, so a request the client abandoned
	// does not keep a lookup running; not by the score budget, which may
	// already be spent.
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	l, err := e.labelsFn(ctx, ns)
	if err != nil {
		return nil
	}
	if l == nil {
		return map[string]string{}
	}
	return l
}

func (e *Engine) readNamespaceLabels(ctx context.Context, ns string) (map[string]string, error) {
	c, err := e.clients()
	if err != nil {
		return nil, err
	}
	n, err := c.Typed.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return n.Labels, nil
}
