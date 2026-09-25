package normalize

import (
	"net/http/httptest"
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
