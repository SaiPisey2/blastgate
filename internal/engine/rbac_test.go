package engine

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/SaiPisey2/blastgate/internal/normalize"
)

func rbacAction(verb, resource, ns, name string) normalize.Action {
	return normalize.Action{Verb: verb, Group: rbacGroup, Version: "v1", Resource: resource, Namespace: ns, Name: name, Principal: alice}
}

// An approver of an access grant sees what is granted: the binding's role
// and subjects, or a role's rules, in the impact's effect -- which the
// impact digest, and so the token, covers.
func TestAuthorityImpactNamesTheGrant(t *testing.T) {
	cases := []struct {
		name      string
		a         normalize.Action
		body      string
		obj, expl string
	}{
		{"cluster role binding", rbacAction("create", "clusterrolebindings", "", ""),
			`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"agent-view"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"view"},"subjects":[{"kind":"User","name":"coding-agent"},{"kind":"ServiceAccount","name":"ci","namespace":"demo"}]}`,
			"rbac.authorization.k8s.io/ClusterRoleBinding//agent-view", "binds ClusterRole/view to User coding-agent, ServiceAccount demo/ci"},
		{"role binding update", rbacAction("update", "rolebindings", "demo", "edit-it"),
			`{"metadata":{"name":"edit-it","namespace":"demo"},"roleRef":{"kind":"Role","name":"editor"},"subjects":[{"kind":"Group","name":"devs"}]}`,
			"rbac.authorization.k8s.io/RoleBinding/demo/edit-it", "binds Role/editor to Group devs"},
		{"binding with no subjects", rbacAction("create", "rolebindings", "demo", ""),
			`{"metadata":{"name":"empty"},"roleRef":{"kind":"Role","name":"r"}}`,
			"rbac.authorization.k8s.io/RoleBinding/demo/empty", "binds Role/r to no subjects"},
		{"role", rbacAction("create", "roles", "demo", ""),
			`{"metadata":{"name":"reader"},"rules":[{"verbs":["list","get"],"resources":["secrets","pods"]},{"verbs":["create"],"resources":["deployments"]}]}`,
			"rbac.authorization.k8s.io/Role/demo/reader", "allows get,list on pods,secrets; create on deployments"},
		{"cluster role with urls", rbacAction("create", "clusterroles", "", ""),
			`{"metadata":{"name":"metrics"},"rules":[{"verbs":["get"],"nonResourceURLs":["/metrics"]}]}`,
			"rbac.authorization.k8s.io/ClusterRole//metrics", "allows get on /metrics"},
		{"aggregated cluster role", rbacAction("create", "clusterroles", "", ""),
			`{"metadata":{"name":"agg"},"aggregationRule":{"clusterRoleSelectors":[{"matchLabels":{"x":"y"}}]},"rules":[]}`,
			"rbac.authorization.k8s.io/ClusterRole//agg", "aggregates the rules of other ClusterRoles"},
		{"empty role", rbacAction("create", "roles", "demo", ""),
			`{"metadata":{"name":"nothing"}}`,
			"rbac.authorization.k8s.io/Role/demo/nothing", "allows nothing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var seen []*http.Request
			e := apiServer(t, "", "", 200, &seen)
			i := e.assessMutation(context.Background(), c.a, []byte(c.body))
			if i.Class != ClassAuthority || !i.Measured || len(i.Effects) != 1 {
				t.Fatalf("impact = %+v", i)
			}
			if ef := i.Effects[0]; ef.Kind != "grants" || ef.Object != c.obj || ef.Explanation != c.expl {
				t.Errorf("effect = %+v\\nwant object %q explanation %q", ef, c.obj, c.expl)
			}
			if len(seen) != 0 {
				t.Error("an authority grant was sent to the API server during scoring")
			}
		})
	}
}

// What cannot be read is unmeasured -- and still AUTHORITY. An
// unmeasured impact of any other class (Unmeasured is TERMINAL) would
// need only one approver, so a body crafted to fail decoding would turn
// an access grant into a single-person approval.
func TestAuthorityImpactFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		a    normalize.Action
		body string
	}{
		{"generateName", rbacAction("create", "clusterrolebindings", "", ""), `{"metadata":{"generateName":"x-"},"roleRef":{"kind":"ClusterRole","name":"admin"}}`},
		{"no name", rbacAction("create", "clusterrolebindings", "", ""), `{"roleRef":{"kind":"ClusterRole","name":"admin"}}`},
		{"not json", rbacAction("create", "clusterrolebindings", "", ""), "kind: ClusterRoleBinding\nmetadata:\n  name: x\n"},
		{"wrong types", rbacAction("create", "clusterrolebindings", "", ""), `{"metadata":{"name":"x"},"subjects":"everyone"}`},
		{"empty body", rbacAction("create", "clusterrolebindings", "", ""), ``},
		{"patch", rbacAction("patch", "clusterrolebindings", "", "x"), `{"subjects":[{"kind":"User","name":"u"}]}`},
		{"no role", rbacAction("create", "clusterrolebindings", "", ""), `{"metadata":{"name":"x"},"subjects":[{"kind":"User","name":"u"}]}`},
		{"name differs from path", rbacAction("update", "clusterrolebindings", "", "x"), `{"metadata":{"name":"y"},"roleRef":{"kind":"ClusterRole","name":"admin"}}`},
		{"namespace differs from path", rbacAction("create", "rolebindings", "demo", ""), `{"metadata":{"name":"x","namespace":"prod"},"roleRef":{"kind":"Role","name":"r"}}`},
		{"namespaced without namespace", rbacAction("create", "rolebindings", "", ""), `{"metadata":{"name":"x"},"roleRef":{"kind":"Role","name":"r"}}`},
		{"unprintable name", rbacAction("create", "clusterrolebindings", "", ""), "{\"metadata\":{\"name\":\"agent‮weiv\"},\"roleRef\":{\"kind\":\"ClusterRole\",\"name\":\"admin\"}}"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var seen []*http.Request
			e := apiServer(t, "", "", 200, &seen)
			i := e.assessMutation(context.Background(), c.a, []byte(c.body))
			if i.Class != ClassAuthority || i.Measured || i.Reason == "" {
				t.Fatalf("impact = %+v, want unmeasured AUTHORITY", i)
			}
			if len(i.Effects) != 1 || i.Effects[0].Explanation != "changes who may act in the cluster" {
				t.Errorf("effects = %+v", i.Effects)
			}
			if len(seen) != 0 {
				t.Error("an authority grant was sent to the API server during scoring")
			}
		})
	}
}

// The API server matches field names exactly; encoding/json does not. A
// body with both "subjects" and "Subjects" is stored with the first, and
// the approver must be shown that one, not the decoy.
func TestAuthorityImpactDecodesCaseSensitively(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, "", "", 200, &seen)
	body := `{"metadata":{"name":"x"},"roleRef":{"kind":"ClusterRole","name":"cluster-admin"},` +
		`"subjects":[{"kind":"User","name":"intruder"}],"Subjects":[{"kind":"User","name":"harmless"}],` +
		`"RoleRef":{"kind":"ClusterRole","name":"view"}}`
	i := e.assessMutation(context.Background(), rbacAction("create", "clusterrolebindings", "", ""), []byte(body))
	if len(i.Effects) != 1 || i.Effects[0].Explanation != "binds ClusterRole/cluster-admin to User intruder" {
		t.Fatalf("effects = %+v", i.Effects)
	}
}

// Every string from the body is cleaned and capped before it is shown.
func TestAuthorityImpactSanitisesAndCaps(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, "", "", 200, &seen)
	var subj []string
	for i := 0; i < 20; i++ {
		subj = append(subj, `{"kind":"User","name":"u`+itoa(i)+`"}`)
	}
	long := strings.Repeat("a", 2000)
	body := "{\"metadata\":{\"name\":\"x\"},\"roleRef\":{\"kind\":\"ClusterRole\",\"name\":\"ad‮min\\u0007\"}," +
		"\"subjects\":[{\"kind\":\"User\",\"name\":\"" + long + "\"}," + strings.Join(subj, ",") + "]}"
	i := e.assessMutation(context.Background(), rbacAction("create", "clusterrolebindings", "", ""), []byte(body))
	if len(i.Effects) != 1 || !i.Measured {
		t.Fatalf("impact = %+v", i)
	}
	expl := i.Effects[0].Explanation
	if !strings.HasPrefix(expl, "binds ClusterRole/admin to User aaa") {
		t.Errorf("explanation not cleaned: %q", expl)
	}
	for _, r := range expl {
		if unprintable(r) {
			t.Fatalf("explanation keeps unprintable rune %U: %q", r, expl)
		}
	}
	if n := len([]rune(expl)); n > maxRBACExplanation {
		t.Errorf("explanation is %d runes, cap %d", n, maxRBACExplanation)
	}
	// Eight subjects at the longest name each run past the cap.
	var longSubj []string
	for i := 0; i < maxRBACSubjects; i++ {
		longSubj = append(longSubj, `{"kind":"User","name":"`+strings.Repeat(string(rune('a'+i)), maxRBACString)+`"}`)
	}
	body = `{"metadata":{"name":"x"},"roleRef":{"kind":"ClusterRole","name":"view"},"subjects":[` + strings.Join(longSubj, ",") + `]}`
	i = e.assessMutation(context.Background(), rbacAction("create", "clusterrolebindings", "", ""), []byte(body))
	if n := len([]rune(i.Effects[0].Explanation)); n != maxRBACExplanation {
		t.Errorf("explanation of eight long subjects is %d runes, want the cap %d", n, maxRBACExplanation)
	}
	body = `{"metadata":{"name":"x"},"roleRef":{"kind":"ClusterRole","name":"view"},"subjects":[` + strings.Join(subj, ",") + `]}`
	i = e.assessMutation(context.Background(), rbacAction("create", "clusterrolebindings", "", ""), []byte(body))
	if expl := i.Effects[0].Explanation; !strings.HasSuffix(expl, "User u7, and 12 more") {
		t.Errorf("subjects not capped: %q", expl)
	}
}

// The binding shown is part of the impact digest: an identical retry
// digests the same, a different subject does not.
func TestAuthorityImpactDigestCoversTheGrant(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, "", "", 200, &seen)
	a := rbacAction("create", "clusterrolebindings", "", "")
	one := e.assessMutation(context.Background(), a, []byte(`{"metadata":{"name":"x"},"roleRef":{"kind":"ClusterRole","name":"view"},"subjects":[{"kind":"User","name":"a"}]}`))
	same := e.assessMutation(context.Background(), a, []byte(`{"subjects":[{"name":"a","kind":"User"}],"roleRef":{"name":"view","kind":"ClusterRole"},"metadata":{"name":"x"}}`))
	other := e.assessMutation(context.Background(), a, []byte(`{"metadata":{"name":"x"},"roleRef":{"kind":"ClusterRole","name":"view"},"subjects":[{"kind":"User","name":"b"}]}`))
	if one.Digest() != same.Digest() {
		t.Error("the same grant written in another key order digests differently")
	}
	if one.Digest() == other.Digest() {
		t.Error("a different subject digests the same: the token would not cover what was shown")
	}
}
