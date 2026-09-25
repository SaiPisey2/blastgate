package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"

	"github.com/SaiPisey2/sounding/pkg/cluster"
	"github.com/SaiPisey2/sounding/pkg/disruption"
	"github.com/SaiPisey2/sounding/pkg/selector"

	"github.com/SaiPisey2/blastgate/internal/normalize"
)

// maxBody is the API server's own request limit, used for its responses
// too: an object larger than it cannot have been written by a client.
const maxBody = 3 << 20

// lookups are the cluster reads a mutation's consequences need beyond the
// dry-run itself. An interface so tests can supply Services, Pods and a
// disruption report without a cluster.
type lookups interface {
	Services(ctx context.Context, ns string) ([]corev1.Service, error)
	Pods(ctx context.Context, ns string) ([]corev1.Pod, error)
	Disruption(ctx context.Context, ns string, rm disruption.Removal) (disruption.Report, error)
}

// soundingLookups is the production lookups. A fresh Clients per call for
// the reason Engine.clients gives: sounding's Clients is not safe for the
// concurrent scoring the proxy does.
type soundingLookups struct{ cfg *rest.Config }

func (l soundingLookups) clients() (*cluster.Clients, error) {
	if l.cfg == nil {
		// NewForConfig panics on nil; a panic would kill the request unheld.
		return nil, errors.New("no upstream config to score with")
	}
	return cluster.NewForConfig(l.cfg)
}

func (l soundingLookups) Services(ctx context.Context, ns string) ([]corev1.Service, error) {
	c, err := l.clients()
	if err != nil {
		return nil, err
	}
	return selector.Services(ctx, c, ns)
}

func (l soundingLookups) Pods(ctx context.Context, ns string) ([]corev1.Pod, error) {
	c, err := l.clients()
	if err != nil {
		return nil, err
	}
	return selector.Pods(ctx, c, ns)
}

func (l soundingLookups) Disruption(ctx context.Context, ns string, rm disruption.Removal) (disruption.Report, error) {
	c, err := l.clients()
	if err != nil {
		return disruption.Report{}, err
	}
	return disruption.Assess(ctx, c, ns, rm)
}

// isAuthority reports the writes that change who may act rather than what
// runs. A dry-run would say only that the grant is valid; what the grantee
// then does is not measurable, and none of it is undone by deleting the
// grant afterwards. They are never sent to the API server while scoring.
func isAuthority(a normalize.Action) bool {
	switch {
	case a.Group == "rbac.authorization.k8s.io":
		return true
	case a.Group == "" && a.Resource == "serviceaccounts" && a.Subresource == "token":
		return true
	case a.Group == "certificates.k8s.io" && a.Resource == "certificatesigningrequests" && a.Subresource == "approval":
		return true
	}
	return false
}

// templated are the workloads whose pod template labels decide which
// Services route to their pods, by group.
var templated = map[string]map[string]bool{
	"apps": {"deployments": true, "statefulsets": true, "daemonsets": true, "replicasets": true},
	"":     {"replicationcontrollers": true},
}

// assessMutation measures a create, update or patch by asking the API
// server what it would store -- a dry-run sent as the session's human, so
// their RBAC and every admission webhook have their say -- and comparing
// that with the live object.
func (e *Engine) assessMutation(ctx context.Context, a normalize.Action, body []byte) Impact {
	if isAuthority(a) {
		return Impact{Class: ClassAuthority, Measured: true, Undo: "none", Effects: []Effect{{
			Kind:        "grants",
			Object:      resourceRef(a),
			Explanation: "changes who may act in the cluster",
		}}}
	}
	if a.Principal.Human == "" {
		// Without Impersonate-User the dry-run would run as blastgate's own
		// service account and measure its rights, not the human's.
		return Unmeasured("no human to dry-run as")
	}
	var method string
	switch a.Verb {
	case "create":
		method = http.MethodPost
	case "update":
		method = http.MethodPut
	case "patch":
		method = http.MethodPatch
	default:
		return Unmeasured("verb " + a.Verb + " is not measured by this build")
	}
	if a.Verb != "patch" && !json.Valid(body) {
		// The dry-run declares application/json. A protobuf or YAML body
		// sent under that label is refused, and a refused dry-run is scored
		// as a request the server refuses -- while the real request, with
		// its real Content-Type, would succeed unheld.
		return Unmeasured("a create or update body that is not JSON cannot be dry-run faithfully")
	}
	if _, err := apiPath(a); err != nil {
		return Unmeasured("request path not measured: " + err.Error())
	}

	var before map[string]any
	if a.Verb != "create" {
		// A create has no object yet (and a subresource create, such as a
		// binding, has nothing to GET).
		obj, status, err := e.fetch(ctx, a, http.MethodGet, false, nil)
		switch {
		case err != nil:
			return Unmeasured("live object not read: " + err.Error())
		case status == http.StatusNotFound:
			// No "before": the dry-run answers for the missing object.
		case status/100 != 2:
			// A before this build could not see is not an empty before: a
			// relabel or scale-down would go unmeasured and look harmless.
			return Unmeasured(fmt.Sprintf("live object read returned %d", status))
		default:
			before = obj
		}
	}

	after, status, err := e.fetch(ctx, a, method, true, body)
	switch {
	case err != nil:
		return Unmeasured("dry-run failed: " + err.Error())
	case status == http.StatusForbidden || status == http.StatusNotFound:
		// The human may not do this, or the object is not there: both are
		// decided before any dry-run-specific path, so the real request is
		// refused the same way and changes nothing. Recorded so the audit
		// shows the attempt. (Ruling P1-R13.)
		return Impact{Class: ClassRead, Measured: true, DryRunRejected: true, Undo: "none"}
	case status/100 != 2:
		// Every other refusal can be the dry-run's alone: a 400 from an
		// admission webhook that does not support dry-run, a 409 or 422
		// that a later state or the real body avoids, a 415 for a type the
		// real request sends differently, a throttle, a redirect, a 5xx.
		// The real request may succeed, so none of them is "changes
		// nothing".
		return Unmeasured(fmt.Sprintf("dry-run returned %d", status))
	}

	i := Impact{Class: ClassReversible, Measured: true, Undo: "objects"}
	kind := "changes"
	if a.Verb == "create" {
		kind = "creates"
	}
	i.Effects = append(i.Effects, Effect{Kind: kind, Object: createdRef(a, after, body)})
	if before == nil {
		return i
	}

	if fail := e.scaleDown(ctx, a, before, after, &i); fail != "" {
		return Unmeasured(fail)
	}
	if templated[a.Group][a.Resource] && a.Subresource == "" {
		bl := nestedStringMap(before, "spec", "template", "metadata", "labels")
		al := nestedStringMap(after, "spec", "template", "metadata", "labels")
		if !maps.Equal(bl, al) {
			svcs, err := e.look.Services(ctx, a.Namespace)
			if err != nil {
				return Unmeasured("services not read: " + err.Error())
			}
			for _, name := range selector.Orphaned(svcs, bl, al) {
				setEndpoints(&i, name, 0)
				i.Effects = append(i.Effects, Effect{
					Kind:        "orphans",
					Object:      "Service/" + a.Namespace + "/" + name,
					Explanation: "pod template labels no longer match its selector",
				})
			}
		}
	}
	if a.Group == "" && a.Resource == "services" && a.Subresource == "" {
		bs := nestedStringMap(before, "spec", "selector")
		as := nestedStringMap(after, "spec", "selector")
		if !maps.Equal(bs, as) {
			pods, err := e.look.Pods(ctx, a.Namespace)
			if err != nil {
				return Unmeasured("pods not read: " + err.Error())
			}
			nb, na := selector.Retargeted(pods, bs, as)
			setEndpoints(&i, a.Name, na)
			i.Effects = append(i.Effects, Effect{
				Kind:        "retargets",
				Object:      objectRefOf(a, after),
				Explanation: fmt.Sprintf("pods %d→%d", nb, na),
			})
		}
	}
	return i
}

// scaleDown adds the worst-case disruption of a replica decrease to i. It
// returns a reason when the decrease cannot be measured: a scale-down whose
// pods cannot be found is not a scale-down that removes nothing.
func (e *Engine) scaleDown(ctx context.Context, a normalize.Action, before, after map[string]any, i *Impact) string {
	b, okb := nestedInt(before, "spec", "replicas")
	n, oka := nestedInt(after, "spec", "replicas")
	isScale := a.Subresource == "scale"
	if isScale {
		// autoscaling/v1 Scale's spec.replicas is an omitempty int32: the
		// API server writes a Scale of zero replicas with no replicas at
		// all. Read as "not a scale-down", a scale to zero passed as a
		// plain change.
		if _, ok := nested(before, "spec"); ok && !okb {
			b, okb = 0, true
		}
		if _, ok := nested(after, "spec"); ok && !oka {
			n, oka = 0, true
		}
	}
	if okb && !oka {
		// The live object had replicas and the dry-run's answer has none:
		// whatever it would do to them is unknown, not "unchanged".
		return fmt.Sprintf("replicas missing from the dry-run of %s", a.Resource)
	}
	if !okb || !oka || n >= b {
		return ""
	}
	if !isScale && !(a.Subresource == "" && hasPodSelector(a)) {
		return fmt.Sprintf("replicas decrease on %s, whose pods this build cannot find", a.Resource)
	}
	// The live object's selector: it names the pods running now, which are
	// the ones a scale-down removes.
	sel, err := workloadSelector(before, isScale)
	if err != nil {
		return "scale-down selector: " + err.Error()
	}
	rep, err := e.look.Disruption(ctx, a.Namespace, disruption.Removal{Selector: sel, Count: int(b - n)})
	if err != nil {
		return "scale-down disruption not measured: " + err.Error()
	}
	i.Effects = append(i.Effects, Effect{
		Kind:        "scales-down",
		Object:      objectRefOf(a, before),
		Explanation: fmt.Sprintf("replicas %d→%d", b, n),
	})
	for _, s := range rep.Services {
		setEndpoints(i, s.Name, s.Left)
	}
	i.PDBViolations = append(i.PDBViolations, rep.Violated()...)
	return ""
}

// hasPodSelector names the kinds whose spec.selector is known to select
// the pods spec.replicas counts. A custom resource's spec.selector may mean
// anything.
func hasPodSelector(a normalize.Action) bool {
	if a.Group == "" {
		return a.Resource == "replicationcontrollers"
	}
	return a.Group == "apps" && (a.Resource == "deployments" || a.Resource == "statefulsets" || a.Resource == "replicasets")
}

func setEndpoints(i *Impact, name string, n int) {
	if i.EndpointsLeft == nil {
		i.EndpointsLeft = map[string]int{}
	}
	if old, ok := i.EndpointsLeft[name]; ok && old < n {
		// Two measurements of one Service keep the worse.
		return
	}
	i.EndpointsLeft[name] = n
}

// apiPath is the escaped path of a's object, built from its parsed parts.
// Each segment is escaped on its own: a name is data, and a "/" or "?" in
// it must not become part of the path or query (sounding ruling R7). A
// "." or ".." segment is refused outright, because a server or proxy that
// cleans paths would resolve it to a different object than the one scored.
func apiPath(a normalize.Action) (string, error) {
	if a.Version == "" || a.Resource == "" {
		return "", errors.New("no version or resource")
	}
	if a.Subresource != "" && a.Name == "" {
		return "", errors.New("subresource without a name")
	}
	segs := []string{"api", a.Version}
	if a.Group != "" {
		segs = []string{"apis", a.Group, a.Version}
	}
	// A Namespace's subresources (namespaces/x/finalize) are parsed with
	// the namespace set to its own name; adding it would double the path.
	if a.Namespace != "" && !(a.Group == "" && a.Resource == "namespaces") {
		segs = append(segs, "namespaces", a.Namespace)
	}
	segs = append(segs, a.Resource)
	if a.Name != "" {
		segs = append(segs, a.Name)
	}
	if a.Subresource != "" {
		segs = append(segs, a.Subresource)
	}
	var b strings.Builder
	for _, s := range segs {
		if s == "." || s == ".." {
			return "", errors.New("a dot segment")
		}
		b.WriteString("/")
		b.WriteString(url.PathEscape(s))
	}
	p := b.String()
	if a.Path != "" {
		// The client's own path must name the same object: if normalize and
		// this builder ever disagree, the dry-run would measure one object
		// and the proxy forward to another.
		got, err1 := url.PathUnescape(strings.TrimRight(a.Path, "/"))
		want, err2 := url.PathUnescape(p)
		if err1 != nil || err2 != nil || got != want {
			return "", errors.New("the request path and its parsed action disagree")
		}
	}
	return p, nil
}

// request builds a dry-run or "before" request for a, impersonated as the
// session's human. It returns an error where the brief's signature has
// none: a path that cannot be built safely must stop the measurement, not
// send a request somewhere else.
func (e *Engine) request(ctx context.Context, a normalize.Action, method string, dryRun bool, body []byte) (*http.Request, error) {
	if e.up == nil || e.up.URL == nil {
		return nil, errors.New("no upstream to dry-run against")
	}
	p, err := apiPath(a)
	if err != nil {
		return nil, err
	}
	u := *e.up.URL
	u.User, u.Fragment, u.RawFragment = nil, "", ""
	// Kept, like the proxy's SetURL: an API server behind a path prefix.
	raw := strings.TrimSuffix(e.up.URL.EscapedPath(), "/") + p
	if u.Path, err = url.PathUnescape(raw); err != nil {
		return nil, err
	}
	u.RawPath = raw
	q := url.Values{}
	if method != http.MethodGet {
		// fieldManager, force and fieldValidation change what is stored,
		// so the dry-run must carry them to answer for the real request.
		for k, v := range a.Query {
			q[k] = append([]string(nil), v...)
		}
	}
	if dryRun {
		// Set, not Add: an agent's own dryRun value must not leave a second
		// one the server might read instead.
		q.Set("dryRun", "All")
	}
	u.RawQuery = q.Encode()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Accept", "application/json")
	if body != nil {
		ct := "application/json"
		if a.Verb == "patch" {
			ct = a.PatchType
		}
		r.Header.Set("Content-Type", ct)
	}
	r.Header.Set("Impersonate-User", a.Principal.Human)
	r.Header.Set("Impersonate-Extra-Blastgate-Agent", a.Principal.Agent)
	r.Header.Set("Impersonate-Extra-Blastgate-Session", a.Principal.Session)
	return r, nil
}

// Before returns the raw JSON of a's live object, read impersonated as the
// session's human -- the same object assessMutation's dry-run compared
// against, so a snapshot and a scored "before" never disagree. It answers
// (nil, nil) on 404: there is nothing to restore, not a failure to report.
// Any other non-2xx status, an unsafe path, or no human to impersonate is
// an error -- the caller (snapshot.Taker) treats a failed snapshot as a
// reason to refuse forwarding, and a nil result mistaken for "nothing
// there" would forward a write with no way back.
func (e *Engine) Before(ctx context.Context, a normalize.Action) ([]byte, error) {
	if a.Principal.Human == "" {
		// Without Impersonate-User this would read as blastgate's own
		// service account, not the human whose write is about to be
		// forwarded -- the same reason assessMutation refuses it.
		return nil, errors.New("no human to read the live object as")
	}
	r, err := e.request(ctx, a, http.MethodGet, false, nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.httpDo(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := readLimitedBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("live object read returned %d", resp.StatusCode)
	}
	return data, nil
}

// List returns the raw JSON of the collection a deletecollection would
// empty: a LIST of the same path, with the same labelSelector and
// fieldSelector, read impersonated as the session's human -- what the
// API server itself deletes is what that LIST returns. Unlike Before, a
// 404 is an error: a collection that cannot be listed is not an empty
// one, and forwarding on it would delete with no way back.
func (e *Engine) List(ctx context.Context, a normalize.Action) ([]byte, error) {
	if a.Principal.Human == "" {
		return nil, errors.New("no human to list the collection as")
	}
	if a.Name != "" || a.Subresource != "" {
		return nil, errors.New("not a collection")
	}
	r, err := e.request(ctx, a, http.MethodGet, false, nil)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	for _, k := range []string{"labelSelector", "fieldSelector"} {
		v := a.Query[k]
		if len(v) > 1 {
			// normalize sorts repeated values, so which one the API server
			// honours is no longer known; listing by the other one would
			// snapshot a different set than the one deleted.
			return nil, fmt.Errorf("more than one %s", k)
		}
		if len(v) == 1 {
			q.Set(k, v[0])
		}
	}
	r.URL.RawQuery = q.Encode()
	resp, err := e.httpDo(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := readLimitedBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("collection list returned %d", resp.StatusCode)
	}
	return data, nil
}

// readLimitedBody reads resp's body up to maxBody -- the API server's own
// request limit, applied to its responses too, because an object it stored
// larger than its own limit could not have been written by a client. The
// one place this is enforced: Before and fetch both read a response back
// and must refuse the same way past that size, not each carry their own
// copy of the check to fall out of step.
func readLimitedBody(resp *http.Response) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBody {
		return nil, errors.New("response larger than 3 MiB")
	}
	return data, nil
}

// fetch sends one request and decodes a 2xx answer. A non-2xx status comes
// back with a nil object and no error; the caller decides what it means.
func (e *Engine) fetch(ctx context.Context, a normalize.Action, method string, dryRun bool, body []byte) (map[string]any, int, error) {
	r, err := e.request(ctx, a, method, dryRun, body)
	if err != nil {
		return nil, 0, err
	}
	resp, err := e.httpDo(r)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := readLimitedBody(resp)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, resp.StatusCode, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	// Numbers stay exact: replicas read as float64 would still be right,
	// but nothing here should depend on that.
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, 0, fmt.Errorf("decoding response: %w", err)
	}
	if obj == nil {
		return nil, 0, errors.New("response is not an object")
	}
	return obj, resp.StatusCode, nil
}

func nested(obj map[string]any, path ...string) (any, bool) {
	var cur any = obj
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[p]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func nestedInt(obj map[string]any, path ...string) (int64, bool) {
	v, ok := nested(obj, path...)
	if !ok {
		return 0, false
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

// nestedStringMap returns nil when the map is absent, which compares equal
// to an empty one: labels removed and labels never set select the same.
func nestedStringMap(obj map[string]any, path ...string) map[string]string {
	v, ok := nested(obj, path...)
	if !ok {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, x := range m {
		if s, ok := x.(string); ok {
			out[k] = s
		}
	}
	return out
}

// workloadSelector returns the selector of the pods obj runs. A Scale
// carries it as a string in status.selector; a workload as a LabelSelector
// in spec.selector (a ReplicationController as a plain map). Absent or
// empty is an error, never "everything" or "nothing".
func workloadSelector(obj map[string]any, isScale bool) (*metav1.LabelSelector, error) {
	if isScale {
		v, _ := nested(obj, "status", "selector")
		s, _ := v.(string)
		if s == "" {
			return nil, errors.New("the scale reports no selector")
		}
		return metav1.ParseToLabelSelector(s)
	}
	v, ok := nested(obj, "spec", "selector")
	m, _ := v.(map[string]any)
	if !ok || len(m) == 0 {
		return nil, errors.New("the workload has no selector")
	}
	_, hasLabels := m["matchLabels"]
	_, hasExprs := m["matchExpressions"]
	if !hasLabels && !hasExprs {
		// A ReplicationController's selector is a bare label map.
		return &metav1.LabelSelector{MatchLabels: nestedStringMap(obj, "spec", "selector")}, nil
	}
	var sel metav1.LabelSelector
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(m, &sel); err != nil {
		return nil, err
	}
	return &sel, nil
}

// objectRefOf names the object obj is, in the group/Kind/namespace/name
// form fromFinding uses. A subresource names the object the server
// returned (a Scale is autoscaling/Scale). The name is a's when it has
// one (createdRef supplies a create body's own name); otherwise it is
// generateName when set, since the dry-run invents
// a fresh random name each time and the digest of an identical retry would
// otherwise never match its approval.
func objectRefOf(a normalize.Action, obj map[string]any) string {
	kind, _ := obj["kind"].(string)
	if kind == "" {
		kind = a.Resource
	}
	group := a.Group
	if av, ok := obj["apiVersion"].(string); ok && av != "" {
		group = ""
		if g, _, found := strings.Cut(av, "/"); found {
			group = g
		}
	}
	name := a.Name
	if name == "" {
		if gn, _ := nested(obj, "metadata", "generateName"); gn != nil && gn != "" {
			name, _ = gn.(string)
		} else if n, _ := nested(obj, "metadata", "name"); n != nil {
			name, _ = n.(string)
		}
	}
	ref := kind + "/" + a.Namespace + "/" + name
	if group != "" {
		ref = group + "/" + ref
	}
	return ref
}

// createdRef is objectRefOf for the request's own object. A create that
// names its object in the body is named by it even when generateName is
// also set -- the server ignores generateName then, and so must the ref;
// only a create with no name falls back to generateName.
func createdRef(a normalize.Action, after map[string]any, body []byte) string {
	if a.Verb == "create" && a.Name == "" {
		var req struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if json.Unmarshal(body, &req) == nil && req.Metadata.Name != "" {
			a.Name = req.Metadata.Name
		}
	}
	return objectRefOf(a, after)
}

// resourceRef names an object that was never read (an authority write is
// not sent anywhere while scoring), so by its resource rather than Kind.
func resourceRef(a normalize.Action) string {
	r := a.Resource
	if a.Subresource != "" {
		r += "/" + a.Subresource
	}
	ref := r + "/" + a.Namespace + "/" + a.Name
	if a.Group != "" {
		ref = a.Group + "/" + ref
	}
	return ref
}
