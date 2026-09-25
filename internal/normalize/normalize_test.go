package normalize

import (
	"net/http/httptest"
	"net/url"
	"testing"
)

var p = Principal{Session: "s1", Human: "alice", Agent: "coding-agent"}

func act(t *testing.T, method, target string, hdr map[string]string) Action {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	a, err := FromRequest(r, p)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	return a
}

func TestFromRequestVerbs(t *testing.T) {
	for _, c := range []struct {
		method, target, verb, res, sub, ns, name, group string
	}{
		{"GET", "/api/v1/namespaces/demo/pods", "list", "pods", "", "demo", "", ""},
		{"GET", "/api/v1/namespaces/demo/pods?watch=true", "watch", "pods", "", "demo", "", ""},
		{"GET", "/api/v1/namespaces/demo/pods/web-1", "get", "pods", "", "demo", "web-1", ""},
		{"GET", "/api/v1/namespaces/demo/pods/web-1/log", "get", "pods", "log", "demo", "web-1", ""},
		{"DELETE", "/apis/apps/v1/namespaces/demo/deployments/web", "delete", "deployments", "", "demo", "web", "apps"},
		{"DELETE", "/api/v1/namespaces/demo/pods", "deletecollection", "pods", "", "demo", "", ""},
		{"DELETE", "/api/v1/namespaces/demo", "delete", "namespaces", "", "", "demo", ""},
		{"PATCH", "/apis/apps/v1/namespaces/demo/deployments/web/scale", "patch", "deployments", "scale", "demo", "web", "apps"},
		{"POST", "/api/v1/namespaces/demo/pods/web-1/exec?command=sh", "create", "pods", "exec", "demo", "web-1", ""},
		{"POST", "/api/v1/namespaces/demo/configmaps", "create", "configmaps", "", "demo", "", ""},
		{"PUT", "/api/v1/namespaces/demo/configmaps/c", "update", "configmaps", "", "demo", "c", ""},
	} {
		a := act(t, c.method, c.target, nil)
		if a.Verb != c.verb || a.Resource != c.res || a.Subresource != c.sub || a.Namespace != c.ns || a.Name != c.name || a.Group != c.group {
			t.Errorf("%s %s: got %+v", c.method, c.target, a)
		}
		if a.Principal != p || a.Source != "proxy" {
			t.Errorf("principal/source not carried: %+v", a)
		}
	}
}

func TestIsRead(t *testing.T) {
	if !act(t, "GET", "/api/v1/namespaces/demo/pods/web-1/log", nil).IsRead() {
		t.Error("pods/log is a read")
	}
	if act(t, "POST", "/api/v1/namespaces/demo/pods/web-1/exec", nil).IsRead() {
		t.Error("exec is not a read")
	}
}

// Controller ruling P1-R6: kubectl's exec (1.30+) and port-forward (1.31+)
// open over WebSocket, which is an HTTP GET -- RequestInfoFactory reports
// verb "get" for them just as it would for a genuine read, and a proxy
// subresource can likewise be a GET that reaches an arbitrary endpoint.
// None of these may be treated as a read regardless of verb.
func TestInteractiveSubresourcesAreNotReadsEvenAsGET(t *testing.T) {
	for _, target := range []string{
		"/api/v1/namespaces/demo/pods/web-1/exec?command=sh",
		"/api/v1/namespaces/demo/pods/web-1/attach",
		"/api/v1/namespaces/demo/pods/web-1/portforward",
		"/api/v1/namespaces/demo/pods/web-1/proxy/x",
		"/api/v1/namespaces/demo/services/web/proxy/x",
	} {
		a := act(t, "GET", target, nil)
		if a.IsRead() {
			t.Errorf("GET %s: %+v treated as a read", target, a)
		}
	}
}

// Discovery and non-resource paths (/api, /apis, /version, /openapi/v3)
// are reads with no resource; they must not error.
func TestNonResourceRequestsAreReads(t *testing.T) {
	for _, target := range []string{"/api", "/apis", "/version", "/openapi/v3", "/apis/apps/v1"} {
		a := act(t, "GET", target, nil)
		if !a.IsRead() {
			t.Errorf("%s: %+v not a read", target, a)
		}
	}
}

// A non-GET to a non-resource path is nothing blastgate understands.
func TestNonResourceWriteIsRefused(t *testing.T) {
	r := httptest.NewRequest("POST", "/version", nil)
	if _, err := FromRequest(r, p); err == nil {
		t.Error("POST /version normalised without error")
	}
}

func TestPatchTypeAndSemanticQueryKept(t *testing.T) {
	a := act(t, "PATCH", "/apis/apps/v1/namespaces/demo/deployments/web?fieldManager=kubectl&force=true&pretty=true&timeout=30s",
		map[string]string{"Content-Type": "application/apply-patch+yaml"})
	if a.PatchType != "application/apply-patch+yaml" {
		t.Errorf("patch type %q", a.PatchType)
	}
	if a.Query["fieldManager"][0] != "kubectl" || a.Query["force"][0] != "true" {
		t.Errorf("semantic query dropped: %v", a.Query)
	}
	if _, ok := a.Query["pretty"]; ok {
		t.Error("presentation-only parameter kept")
	}
	if _, ok := a.Query["timeout"]; ok {
		t.Error("timeout kept; it does not change what the request does")
	}
}

func TestDigestIgnoresKeyOrderAndWhitespace(t *testing.T) {
	a := act(t, "PUT", "/api/v1/namespaces/demo/configmaps/c", map[string]string{"Content-Type": "application/json"})
	d1 := RequestDigest(a, []byte(`{"data":{"k":"v"},"kind":"ConfigMap"}`))
	d2 := RequestDigest(a, []byte("{\n  \"kind\": \"ConfigMap\",\n  \"data\": {\"k\": \"v\"}\n}"))
	if d1 != d2 {
		t.Error("reordered/reformatted JSON changed the digest")
	}
}

func TestDigestChangesWithSemantics(t *testing.T) {
	a := act(t, "PUT", "/api/v1/namespaces/demo/configmaps/c", map[string]string{"Content-Type": "application/json"})
	if RequestDigest(a, []byte(`{"data":{"k":"v"}}`)) == RequestDigest(a, []byte(`{"data":{"k":"w"}}`)) {
		t.Error("a different value produced the same digest")
	}
	b := a
	b.Name = "other"
	if RequestDigest(a, []byte(`{}`)) == RequestDigest(b, []byte(`{}`)) {
		t.Error("a different target produced the same digest")
	}
	c := a
	c.Principal.Session = "s2"
	if RequestDigest(a, []byte(`{}`)) != RequestDigest(c, []byte(`{}`)) {
		t.Error("the digest must describe the request, not who sent it")
	}
}

func TestDigestCanonicalisesApplyYAML(t *testing.T) {
	a := act(t, "PATCH", "/apis/apps/v1/namespaces/demo/deployments/web?fieldManager=kubectl",
		map[string]string{"Content-Type": "application/apply-patch+yaml"})
	y := []byte("kind: Deployment\nspec:\n  replicas: 0\n")
	j := []byte(`{"spec":{"replicas":0},"kind":"Deployment"}`)
	if RequestDigest(a, y) != RequestDigest(a, j) {
		t.Error("equivalent YAML and JSON apply bodies digest differently")
	}
}

func TestDigestOfUnparseableBodyIsStable(t *testing.T) {
	a := act(t, "POST", "/api/v1/namespaces/demo/configmaps", map[string]string{"Content-Type": "application/json"})
	if RequestDigest(a, []byte("{not json")) != RequestDigest(a, []byte("{not json")) {
		t.Error("unstable digest")
	}
	if RequestDigest(a, []byte("{not json")) == RequestDigest(a, []byte("{not json!")) {
		t.Error("different raw bodies collided")
	}
}

// Controller ruling P1-R5: RequestInfo has no field for what follows a
// proxy subresource, so two different proxied endpoints with the same
// empty body would otherwise digest identically -- one approval could
// release a request to a different endpoint than the one it was approved
// for.
func TestDigestSeparatesProxySubPaths(t *testing.T) {
	foo := act(t, "POST", "/api/v1/namespaces/demo/pods/web-1/proxy/foo", nil)
	bar := act(t, "POST", "/api/v1/namespaces/demo/pods/web-1/proxy/bar", nil)
	if RequestDigest(foo, nil) == RequestDigest(bar, nil) {
		t.Error("different proxy sub-paths produced the same digest")
	}

	q1 := act(t, "POST", "/api/v1/namespaces/demo/pods/web-1/proxy/foo?port=8080", nil)
	q2 := act(t, "POST", "/api/v1/namespaces/demo/pods/web-1/proxy/foo?port=9090", nil)
	if RequestDigest(q1, nil) == RequestDigest(q2, nil) {
		t.Error("same proxy sub-path with a different query produced the same digest")
	}
}

func TestIdenticalRetryDigestsEqual(t *testing.T) {
	a1 := act(t, "PATCH", "/apis/apps/v1/namespaces/demo/deployments/web?fieldManager=kubectl",
		map[string]string{"Content-Type": "application/apply-patch+yaml"})
	a2 := act(t, "PATCH", "/apis/apps/v1/namespaces/demo/deployments/web?fieldManager=kubectl",
		map[string]string{"Content-Type": "application/apply-patch+yaml"})
	body := []byte("kind: Deployment\nspec:\n  replicas: 0\n")
	if RequestDigest(a1, body) != RequestDigest(a2, body) {
		t.Error("an identical retry, including path, produced a different digest")
	}
}

func TestPatchTypeNormalizesMediaTypeParameters(t *testing.T) {
	a := act(t, "PATCH", "/apis/apps/v1/namespaces/demo/deployments/web",
		map[string]string{"Content-Type": "application/merge-patch+json; charset=utf-8"})
	if a.PatchType != "application/merge-patch+json" {
		t.Errorf("patch type %q; charset parameter should be stripped", a.PatchType)
	}
	bare := act(t, "PATCH", "/apis/apps/v1/namespaces/demo/deployments/web",
		map[string]string{"Content-Type": "application/merge-patch+json"})
	if RequestDigest(a, []byte("{}")) != RequestDigest(bare, []byte("{}")) {
		t.Error("charset parameter changed the digest")
	}
}

func TestPatchTypeKeptVerbatimOnParseError(t *testing.T) {
	a := act(t, "PATCH", "/apis/apps/v1/namespaces/demo/deployments/web",
		map[string]string{"Content-Type": "not a media type;;;"})
	if a.PatchType != "not a media type;;;" {
		t.Errorf("patch type %q; unparseable content-type should be kept as-is", a.PatchType)
	}
}

// Final review I1: kubectl opens exec, attach and port-forward over
// WebSocket (GET) and falls back to SPDY (POST) when that fails. The API
// server authorises both as "create"; if the digests differed, one
// command would leave two pending approvals, and denying the one it
// reported would leave its twin approvable.
func TestInteractiveVerbIsCreateOverEitherTransport(t *testing.T) {
	up := map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"}
	spdy := map[string]string{"Connection": "Upgrade", "Upgrade": "SPDY/3.1"}
	for _, target := range []string{
		"/api/v1/namespaces/demo/pods/web-1/exec?command=psql&command=-c&command=drop+table+x&stdout=true&stderr=true",
		"/api/v1/namespaces/demo/pods/web-1/attach?stdin=true&stdout=true",
		"/api/v1/namespaces/demo/pods/web-1/portforward?ports=8080",
	} {
		ws, sp := act(t, "GET", target, up), act(t, "POST", target, spdy)
		if ws.Verb != "create" || sp.Verb != "create" {
			t.Errorf("%s: verbs %q (GET) and %q (POST), want create", target, ws.Verb, sp.Verb)
		}
		if RequestDigest(ws, nil) != RequestDigest(sp, nil) {
			t.Errorf("%s: WebSocket and SPDY digests differ", target)
		}
	}
}

// Final review I5: an upgraded connection is a bidirectional stream, not a
// read, whatever the subresource -- a KubeVirt VNC or serial console is a
// GET upgrade on a subresource blastgate has no special case for.
func TestUpgradeIsNeverARead(t *testing.T) {
	target := "/apis/subresources.kubevirt.io/v1/namespaces/demo/virtualmachineinstances/vm/vnc"
	plain := act(t, "GET", target, nil)
	up := act(t, "GET", target, map[string]string{"Connection": "keep-alive, Upgrade", "Upgrade": "websocket"})
	if !up.Upgrade || up.IsRead() {
		t.Errorf("upgrade GET %+v treated as a read", up)
	}
	if plain.Upgrade || !plain.IsRead() {
		t.Errorf("plain GET %+v not a read", plain)
	}
	if RequestDigest(plain, nil) == RequestDigest(up, nil) {
		t.Error("an upgrade and a plain GET of the same path digest the same")
	}
}

// Final review minor 1: a "." or ".." segment, or an empty one, is a path
// a cleaning server or proxy may resolve to a different object than the
// one parsed -- for a read too, which is never scored.
func TestDotAndEmptySegmentsAreRefused(t *testing.T) {
	for _, target := range []string{
		"/api/v1/namespaces/demo/pods/../secrets",
		"/api/v1/namespaces/demo/pods/%2e%2e/secrets",
		"/api/v1/namespaces/demo/./pods",
		"/api/v1/namespaces//pods",
		"/api/v1/namespaces/demo/pods//",
		"//api/v1/namespaces",
	} {
		// ParseRequestURI, as net/http's server does: URL.Parse would
		// clean the dots away and url.Parse would read "//api" as a host.
		r := httptest.NewRequest("GET", "/", nil)
		u, err := url.ParseRequestURI(target)
		if err != nil {
			t.Fatal(err)
		}
		r.URL = u
		if a, err := FromRequest(r, p); err == nil {
			t.Errorf("%s normalised to %+v", target, a)
		}
	}
	act(t, "GET", "/", nil)                             // the root is not an empty segment
	act(t, "GET", "/api/v1/namespaces/demo/pods/", nil) // a cleaner resolves this to the same object
}
