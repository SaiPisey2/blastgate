package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/SaiPisey2/sounding/pkg/disruption"

	"github.com/SaiPisey2/blastgate/internal/normalize"
	"github.com/SaiPisey2/blastgate/internal/upstream"
)

type fakeLook struct {
	svcs   []corev1.Service
	pods   []corev1.Pod
	lastRm disruption.Removal
	report disruption.Report
}

func (f *fakeLook) Services(context.Context, string) ([]corev1.Service, error) { return f.svcs, nil }
func (f *fakeLook) Pods(context.Context, string) ([]corev1.Pod, error)         { return f.pods, nil }
func (f *fakeLook) Disruption(_ context.Context, _ string, rm disruption.Removal) (disruption.Report, error) {
	f.lastRm = rm
	return f.report, nil
}

// apiServer answers GET with before and a dryRun=All request with after,
// recording what it saw.
func apiServer(t *testing.T, before, after string, dryStatus int, seen *[]*http.Request) *Engine {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Clone(context.Background()))
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("dryRun") == "All" {
			w.WriteHeader(dryStatus)
			io.WriteString(w, after)
			return
		}
		if before == "" {
			w.WriteHeader(404)
			io.WriteString(w, `{"kind":"Status","code":404}`)
			return
		}
		io.WriteString(w, before)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	up := &upstream.Upstream{URL: u, Normal: http.DefaultTransport}
	e := New(up, 5*time.Second)
	return e
}

var alice = normalize.Principal{Session: "s1", Human: "alice", Agent: "coding-agent"}

func deployment(replicas int, labels string) string {
	return `{"kind":"Deployment","spec":{"replicas":` + itoa(replicas) + `,"selector":{"matchLabels":{"app":"web"}},"template":{"metadata":{"labels":` + labels + `}}}}`
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestScaleDownAssessesDisruptionWorstCase(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, deployment(3, `{"app":"web"}`), deployment(0, `{"app":"web"}`), 200, &seen)
	look := &fakeLook{report: disruption.Report{Services: []disruption.Service{{Name: "web", Ready: 3, Left: 0}}}}
	e.look = look
	a := normalize.Action{Verb: "patch", Group: "apps", Version: "v1", Resource: "deployments", Namespace: "demo", Name: "web", PatchType: "application/merge-patch+json", Principal: alice}
	i := e.assessMutation(context.Background(), a, []byte(`{"spec":{"replicas":0}}`))
	if !i.Measured || i.Class != ClassReversible || i.EndpointsLeft["web"] != 0 {
		t.Fatalf("impact = %+v", i)
	}
	if look.lastRm.Count != 3 || look.lastRm.Selector == nil || look.lastRm.Selector.MatchLabels["app"] != "web" {
		t.Errorf("removal = %+v", look.lastRm)
	}
	// The dry-run and the before read must both act as the human.
	for _, r := range seen {
		if r.Header.Get("Impersonate-User") != "alice" || r.Header.Get("Impersonate-Extra-Blastgate-Agent") != "coding-agent" {
			t.Errorf("request %s %s not impersonated: %v", r.Method, r.URL, r.Header)
		}
	}
}

func TestScaleSubresourceUsesStatusSelector(t *testing.T) {
	var seen []*http.Request
	scale := func(n int) string {
		return `{"kind":"Scale","spec":{"replicas":` + itoa(n) + `},"status":{"selector":"app=web"}}`
	}
	e := apiServer(t, scale(2), scale(1), 200, &seen)
	look := &fakeLook{}
	e.look = look
	a := normalize.Action{Verb: "patch", Group: "apps", Version: "v1", Resource: "deployments", Subresource: "scale", Namespace: "demo", Name: "web", PatchType: "application/merge-patch+json", Principal: alice}
	e.assessMutation(context.Background(), a, []byte(`{"spec":{"replicas":1}}`))
	if look.lastRm.Count != 1 || look.lastRm.Selector.MatchLabels["app"] != "web" {
		t.Errorf("removal = %+v", look.lastRm)
	}
}

func TestTemplateRelabelOrphansService(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, deployment(1, `{"app":"web"}`), deployment(1, `{"app":"web2"}`), 200, &seen)
	e.look = &fakeLook{svcs: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "web"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "web"}}}}}
	a := normalize.Action{Verb: "update", Group: "apps", Version: "v1", Resource: "deployments", Namespace: "demo", Name: "web", Principal: alice}
	i := e.assessMutation(context.Background(), a, []byte(deployment(1, `{"app":"web2"}`)))
	if v, ok := i.EndpointsLeft["web"]; !ok || v != 0 {
		t.Errorf("endpoints = %v, want web:0", i.EndpointsLeft)
	}
}

func TestServiceSelectorRetargetCountsPods(t *testing.T) {
	var seen []*http.Request
	svc := func(sel string) string { return `{"kind":"Service","spec":{"selector":{"app":"` + sel + `"}}}` }
	e := apiServer(t, svc("web"), svc("wbe"), 200, &seen)
	e.look = &fakeLook{pods: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "a", Labels: map[string]string{"app": "web"}}}}}
	a := normalize.Action{Verb: "patch", Version: "v1", Resource: "services", Namespace: "demo", Name: "web", PatchType: "application/merge-patch+json", Principal: alice}
	i := e.assessMutation(context.Background(), a, []byte(`{"spec":{"selector":{"app":"wbe"}}}`))
	if v, ok := i.EndpointsLeft["web"]; !ok || v != 0 {
		t.Errorf("endpoints = %v", i.EndpointsLeft)
	}
}

func TestRejectedDryRunIsRecordedNotHeld(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, `{"kind":"ConfigMap"}`, `{"kind":"Status","code":403}`, 403, &seen)
	e.look = &fakeLook{}
	a := normalize.Action{Verb: "update", Version: "v1", Resource: "configmaps", Namespace: "demo", Name: "c", Principal: alice}
	i := e.assessMutation(context.Background(), a, []byte(`{}`))
	if !i.Measured || !i.DryRunRejected || i.Class != ClassRead {
		t.Errorf("impact = %+v", i)
	}
}

func TestRBACWriteIsAuthorityWithoutDryRun(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, "", "", 200, &seen)
	a := normalize.Action{Verb: "create", Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings", Principal: alice}
	i := e.assessMutation(context.Background(), a, []byte(`{}`))
	if i.Class != ClassAuthority || !i.Measured {
		t.Errorf("impact = %+v", i)
	}
	if len(seen) != 0 {
		t.Error("an authority grant was sent to the API server during scoring")
	}
}

func TestDryRunCarriesQueryAndContentType(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, deployment(1, `{"app":"web"}`), deployment(1, `{"app":"web"}`), 200, &seen)
	e.look = &fakeLook{}
	a := normalize.Action{Verb: "patch", Group: "apps", Version: "v1", Resource: "deployments", Namespace: "demo", Name: "web",
		PatchType: "application/apply-patch+yaml", Query: map[string][]string{"fieldManager": {"kubectl"}, "force": {"true"}}, Principal: alice}
	e.assessMutation(context.Background(), a, []byte("spec:\n  replicas: 1\n"))
	var dry *http.Request
	for _, r := range seen {
		if r.URL.Query().Get("dryRun") == "All" {
			dry = r
		}
	}
	if dry == nil || dry.Method != "PATCH" || dry.Header.Get("Content-Type") != "application/apply-patch+yaml" ||
		dry.URL.Query().Get("fieldManager") != "kubectl" || dry.URL.Query().Get("force") != "true" ||
		!strings.HasSuffix(dry.URL.Path, "/apis/apps/v1/namespaces/demo/deployments/web") {
		t.Fatalf("dry-run request = %+v", dry)
	}
}

// The cases below pin where this implementation fails closed beyond the
// brief: each is a way a mutation could otherwise be scored as harmless.

func TestDryRunServerErrorIsUnmeasured(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, `{"kind":"ConfigMap"}`, `{"kind":"Status","code":500}`, 500, &seen)
	e.look = &fakeLook{}
	a := normalize.Action{Verb: "update", Version: "v1", Resource: "configmaps", Namespace: "demo", Name: "c", Principal: alice}
	if i := e.assessMutation(context.Background(), a, []byte(`{}`)); i.Measured || i.DryRunRejected {
		t.Errorf("a 500 dry-run scored as %+v; the real request may succeed", i)
	}
}

func TestUnreadableBeforeIsUnmeasured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(403)
			return
		}
		io.WriteString(w, deployment(0, `{"app":"web"}`))
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	e := New(&upstream.Upstream{URL: u, Normal: http.DefaultTransport}, 5*time.Second)
	e.look = &fakeLook{}
	a := normalize.Action{Verb: "patch", Group: "apps", Version: "v1", Resource: "deployments", Namespace: "demo", Name: "web", PatchType: "application/merge-patch+json", Principal: alice}
	if i := e.assessMutation(context.Background(), a, []byte(`{"spec":{"replicas":0}}`)); i.Measured {
		t.Errorf("a scale-down with no readable before scored as %+v", i)
	}
}

func TestNonJSONCreateIsUnmeasured(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, "", `{"kind":"ConfigMap"}`, 200, &seen)
	a := normalize.Action{Verb: "create", Version: "v1", Resource: "configmaps", Namespace: "demo", Principal: alice}
	if i := e.assessMutation(context.Background(), a, []byte("\x0a\x02k8s")); i.Measured {
		t.Errorf("protobuf create scored as %+v", i)
	}
	if len(seen) != 0 {
		t.Error("a body that cannot be dry-run faithfully was sent")
	}
}

func TestNoHumanIsUnmeasured(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, `{"kind":"ConfigMap"}`, `{"kind":"ConfigMap"}`, 200, &seen)
	a := normalize.Action{Verb: "update", Version: "v1", Resource: "configmaps", Namespace: "demo", Name: "c", Principal: normalize.Principal{Session: "s1", Agent: "coding-agent"}}
	if i := e.assessMutation(context.Background(), a, []byte(`{}`)); i.Measured || len(seen) != 0 {
		t.Errorf("impact = %+v, %d requests sent as the service account", i, len(seen))
	}
}

func TestCustomResourceScaleDownIsUnmeasured(t *testing.T) {
	var seen []*http.Request
	cr := func(n int) string {
		return `{"kind":"Cluster","apiVersion":"db.example.com/v1","spec":{"replicas":` + itoa(n) + `,"selector":{"matchLabels":{"app":"pg"}}}}`
	}
	e := apiServer(t, cr(3), cr(1), 200, &seen)
	e.look = &fakeLook{}
	a := normalize.Action{Verb: "patch", Group: "db.example.com", Version: "v1", Resource: "clusters", Namespace: "demo", Name: "pg", PatchType: "application/merge-patch+json", Principal: alice}
	if i := e.assessMutation(context.Background(), a, []byte(`{"spec":{"replicas":1}}`)); i.Measured {
		t.Errorf("custom resource scale-down scored as %+v", i)
	}
}

func TestScaleWithoutSelectorIsUnmeasured(t *testing.T) {
	var seen []*http.Request
	scale := func(n int) string { return `{"kind":"Scale","spec":{"replicas":` + itoa(n) + `},"status":{}}` }
	e := apiServer(t, scale(2), scale(1), 200, &seen)
	e.look = &fakeLook{}
	a := normalize.Action{Verb: "patch", Group: "db.example.com", Version: "v1", Resource: "clusters", Subresource: "scale", Namespace: "demo", Name: "pg", PatchType: "application/merge-patch+json", Principal: alice}
	if i := e.assessMutation(context.Background(), a, []byte(`{"spec":{"replicas":1}}`)); i.Measured {
		t.Errorf("scale with no selector scored as %+v", i)
	}
}

func TestPathIsEscapedPerSegment(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, `{"kind":"ConfigMap"}`, `{"kind":"ConfigMap"}`, 200, &seen)
	e.look = &fakeLook{}
	a := normalize.Action{Verb: "update", Version: "v1", Resource: "configmaps", Namespace: "demo", Name: "a/b?c", Principal: alice}
	e.assessMutation(context.Background(), a, []byte(`{}`))
	if len(seen) == 0 {
		t.Fatal("no request sent")
	}
	for _, r := range seen {
		if r.URL.EscapedPath() != "/api/v1/namespaces/demo/configmaps/a%2Fb%3Fc" {
			t.Errorf("path = %s", r.URL.EscapedPath())
		}
	}
	seen = nil
	a.Name = ".."
	if i := e.assessMutation(context.Background(), a, []byte(`{}`)); i.Measured || len(seen) != 0 {
		t.Errorf("dot segment: impact %+v, %d requests", i, len(seen))
	}
}

func TestPathDisagreementIsUnmeasured(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, `{"kind":"ConfigMap"}`, `{"kind":"ConfigMap"}`, 200, &seen)
	a := normalize.Action{Verb: "update", Version: "v1", Resource: "configmaps", Namespace: "demo", Name: "c",
		Path: "/api/v1/namespaces/demo/configmaps/other", Principal: alice}
	if i := e.assessMutation(context.Background(), a, []byte(`{}`)); i.Measured || len(seen) != 0 {
		t.Errorf("impact = %+v, %d requests", i, len(seen))
	}
	a.Path = "/api/v1/namespaces/demo/configmaps/c"
	if i := e.assessMutation(context.Background(), a, []byte(`{}`)); !i.Measured {
		t.Errorf("matching path: impact = %+v", i)
	}
}

func TestNamespaceSubresourcePathIsNotDoubled(t *testing.T) {
	a := normalize.Action{Verb: "update", Version: "v1", Resource: "namespaces", Namespace: "demo", Name: "demo", Subresource: "finalize",
		Path: "/api/v1/namespaces/demo/finalize"}
	if p, err := apiPath(a); err != nil || p != "/api/v1/namespaces/demo/finalize" {
		t.Errorf("path = %q, %v", p, err)
	}
}

func TestCreateWithGenerateNameDigestsStably(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		io.WriteString(w, `{"kind":"Pod","apiVersion":"v1","metadata":{"generateName":"job-","name":"job-`+itoa(n)+`"}}`)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	e := New(&upstream.Upstream{URL: u, Normal: http.DefaultTransport}, 5*time.Second)
	a := normalize.Action{Verb: "create", Version: "v1", Resource: "pods", Namespace: "demo", Principal: alice}
	body := []byte(`{"metadata":{"generateName":"job-"}}`)
	i1, i2 := e.assessMutation(context.Background(), a, body), e.assessMutation(context.Background(), a, body)
	if !i1.Measured || i1.Digest() != i2.Digest() {
		t.Errorf("identical creates digest differently: %+v vs %+v", i1.Effects, i2.Effects)
	}
}

func TestDryRunReplacesAgentDryRunValue(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, `{"kind":"ConfigMap"}`, `{"kind":"ConfigMap"}`, 200, &seen)
	e.look = &fakeLook{}
	a := normalize.Action{Verb: "update", Version: "v1", Resource: "configmaps", Namespace: "demo", Name: "c",
		Query: map[string][]string{"dryRun": {"Bogus"}}, Principal: alice}
	e.assessMutation(context.Background(), a, []byte(`{}`))
	for _, r := range seen {
		if r.Method == http.MethodPut && strings.Join(r.URL.Query()["dryRun"], ",") != "All" {
			t.Errorf("dry-run query = %v", r.URL.Query())
		}
	}
}

// The cross-check against a.Path would hold every write if normalize and
// apiPath disagreed on ordinary paths; this pins that they agree.
func TestAPIPathAgreesWithNormalize(t *testing.T) {
	for _, p := range []string{
		"/api/v1/namespaces/demo/configmaps/c",
		"/api/v1/namespaces/demo/configmaps",
		"/apis/apps/v1/namespaces/demo/deployments/web/scale",
		"/api/v1/namespaces/demo",
		"/api/v1/namespaces/demo/finalize",
		"/api/v1/nodes/n1",
		"/apis/apps/v1/namespaces/demo/deployments/web/",
	} {
		r := httptest.NewRequest(http.MethodPatch, p, nil)
		a, err := normalize.FromRequest(r, alice)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if _, err := apiPath(a); err != nil {
			t.Errorf("%s: %v (action %+v)", p, err, a)
		}
	}
}
