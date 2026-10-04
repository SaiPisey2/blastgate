package engine

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"

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

// crb is a cluster role binding body with the given role and subjects.
func crb(role string, subjects ...string) string {
	return `{"metadata":{"name":"x"},"roleRef":{"kind":"ClusterRole","name":"` + role + `"},"subjects":[` + strings.Join(subjects, ",") + `]}`
}

func user(name string) string { return `{"kind":"User","name":"` + name + `"}` }

func group(name string) string { return `{"kind":"Group","name":"` + name + `"}` }

// assertNotShown is the ruling E-R17 outcome: a grant that cannot be
// shown whole and as sent is unmeasured AUTHORITY with only the generic
// effect, so nothing partial reaches the approver and two people decide
// on "Impact unknown".
func assertNotShown(t *testing.T, what string, i Impact) {
	t.Helper()
	if i.Class != ClassAuthority || i.Measured || len(i.Effects) != 1 || i.Effects[0].Explanation != GrantUnknown {
		t.Errorf("%s: impact = %+v, want unmeasured AUTHORITY with the generic effect", what, i)
	}
}

// The re-review's probe: two long Group subjects push "User attacker"
// past the explanation cap. A cut explanation would hide the attacker
// while the impact still claimed to be measured.
func TestAuthorityImpactNeverHidesASubjectPastTheCap(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, "", "", 200, &seen)
	a := rbacAction("create", "clusterrolebindings", "", "")
	body := crb("cluster-admin", group(strings.Repeat("g", 240)), group(strings.Repeat("h", 240)), user("attacker"))
	i := e.assessMutation(context.Background(), a, []byte(body))
	assertNotShown(t, "attacker probe", i)
	for _, ef := range i.Effects {
		if strings.Contains(ef.Explanation, "gggg") {
			t.Errorf("a partial grant was shown: %q", ef.Explanation)
		}
	}
	// Short enough to show whole: every subject is there, attacker included.
	i = e.assessMutation(context.Background(), a, []byte(crb("cluster-admin", group("ops"), user("attacker"))))
	if !i.Measured || i.Effects[0].Explanation != "binds ClusterRole/cluster-admin to Group ops, User attacker" {
		t.Errorf("short binding: %+v", i)
	}
}

// A list longer than its cap is not shown with "and N more": the hidden
// entries are exactly the ones that matter (impersonate, secrets).
func TestAuthorityImpactListOverflowIsUnmeasured(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, "", "", 200, &seen)
	crbA := rbacAction("create", "clusterrolebindings", "", "")
	crA := rbacAction("create", "clusterroles", "", "")
	var eight, nine []string
	for i := 0; i < 9; i++ {
		u := user(fmt.Sprintf("u%d", i))
		if i < 8 {
			eight = append(eight, u)
		}
		nine = append(nine, u)
	}
	if i := e.assessMutation(context.Background(), crbA, []byte(crb("view", eight...))); !i.Measured || !strings.HasSuffix(i.Effects[0].Explanation, "User u7") {
		t.Errorf("eight subjects should show whole: %+v", i)
	}
	assertNotShown(t, "nine subjects", e.assessMutation(context.Background(), crbA, []byte(crb("view", nine...))))

	role := func(rules ...string) []byte {
		return []byte(`{"metadata":{"name":"r"},"rules":[` + strings.Join(rules, ",") + `]}`)
	}
	rule := func(verbs, resources string) string {
		return `{"verbs":[` + verbs + `],"resources":[` + resources + `]}`
	}
	six := `"a1","a2","a3","a4","a5","a6"`
	if i := e.assessMutation(context.Background(), crA, role(rule(six, `"pods"`))); !i.Measured {
		t.Errorf("six verbs should show whole: %+v", i)
	}
	// "impersonate" sorts after the padding and would fall past the cap.
	assertNotShown(t, "seven verbs", e.assessMutation(context.Background(), crA, role(rule(six+`,"impersonate"`, `"users"`))))
	assertNotShown(t, "seven resources", e.assessMutation(context.Background(), crA, role(rule(`"get"`, six+`,"secrets"`))))
	var rules []string
	for i := 0; i < 6; i++ {
		rules = append(rules, rule(`"get"`, fmt.Sprintf(`"r%d"`, i)))
	}
	if i := e.assessMutation(context.Background(), crA, role(rules...)); !i.Measured {
		t.Errorf("six rules should show whole: %+v", i)
	}
	assertNotShown(t, "seven rules", e.assessMutation(context.Background(), crA, role(append(rules, rule(`"*"`, `"secrets"`))...)))
	// Rule entries may carry "/".
	if i := e.assessMutation(context.Background(), crA, role(rule(`"create"`, `"pods/exec"`), `{"verbs":["get"],"nonResourceURLs":["/metrics"]}`)); !i.Measured ||
		i.Effects[0].Explanation != "allows create on pods/exec; get on /metrics" {
		t.Errorf("slashes in rule entries: %+v", i)
	}
}

// A string that cleaning would change, or that holds the explanation's
// own separators, is never shown altered: the approver would read a
// different name than the one bound.
func TestAuthorityImpactAlteredStringsAreUnmeasured(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, "", "", 200, &seen)
	a := rbacAction("create", "clusterrolebindings", "", "")
	for name, body := range map[string]string{
		"zero-width space in a subject": crb("view", user("atta\u200bcker")),
		"bidi override in a subject":    crb("view", user("ad\u202enimda")),
		"control rune in a subject":     crb("view", user("a\u0007b")),
		"subject over 253 runes":        crb("view", user(strings.Repeat("a", 254))),
		"comma in a subject":            crb("view", user("x, User root")),
		"space in a subject":            crb("view", user("x y")),
		"slash in a subject":            crb("view", user("a/b")),
		"slash in a namespace":          crb("view", `{"kind":"ServiceAccount","name":"ci","namespace":"a/b"}`),
		"zero-width space in the role":  crb("vi\u200bew", user("u")),
		"role over 253 runes":           crb(strings.Repeat("r", 254), user("u")),
		"semicolon in the role":         crb("view;admin", user("u")),
		"empty subject name":            crb("view", user("")),
	} {
		assertNotShown(t, name, e.assessMutation(context.Background(), a, []byte(body)))
	}
	crA := rbacAction("create", "clusterroles", "", "")
	for name, body := range map[string]string{
		"zero-width space in a verb": `{"metadata":{"name":"r"},"rules":[{"verbs":["g\u200bet"],"resources":["pods"]}]}`,
		"comma in a resource":        `{"metadata":{"name":"r"},"rules":[{"verbs":["get"],"resources":["pods,secrets"]}]}`,
		"resource over 253 runes":    `{"metadata":{"name":"r"},"rules":[{"verbs":["get"],"resources":["` + strings.Repeat("p", 254) + `"]}]}`,
	} {
		assertNotShown(t, name, e.assessMutation(context.Background(), crA, []byte(body)))
	}
	// A 253-rune subject is shown whole.
	if i := e.assessMutation(context.Background(), a, []byte(crb("view", user(strings.Repeat("a", 253))))); !i.Measured {
		t.Errorf("a 253-rune subject should show whole: %+v", i)
	}
}

// The API server keeps a namespace on a User or Group subject but ignores
// it: the binding grants the cluster-wide identity. Showing
// "User kube-system/attacker" would read as a namespaced identity that
// does not exist, so only a ServiceAccount carries its namespace.
func TestAuthorityImpactShowsNamespaceOnlyForServiceAccounts(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, "", "", 200, &seen)
	a := rbacAction("create", "clusterrolebindings", "", "")
	for body, want := range map[string]string{
		crb("cluster-admin", `{"kind":"User","name":"attacker","namespace":"kube-system"}`):     "binds ClusterRole/cluster-admin to User attacker",
		crb("cluster-admin", `{"kind":"Group","name":"ops","namespace":"kube-system"}`):         "binds ClusterRole/cluster-admin to Group ops",
		crb("cluster-admin", `{"kind":"User","name":"attacker","namespace":"x, User root"}`):    "binds ClusterRole/cluster-admin to User attacker",
		crb("cluster-admin", `{"kind":"ServiceAccount","name":"ci","namespace":"kube-system"}`): "binds ClusterRole/cluster-admin to ServiceAccount kube-system/ci",
	} {
		i := e.assessMutation(context.Background(), a, []byte(body))
		if !i.Measured || len(i.Effects) != 1 || i.Effects[0].Explanation != want {
			t.Errorf("%s: impact = %+v, want %q", body, i, want)
		}
	}
	// The same grant with and without the ignored namespace reads and
	// digests the same, as the server stores the same permission.
	with := e.assessMutation(context.Background(), a, []byte(crb("view", `{"kind":"User","name":"u","namespace":"demo"}`)))
	without := e.assessMutation(context.Background(), a, []byte(crb("view", user("u"))))
	if with.Digest() != without.Digest() {
		t.Error("an ignored namespace changed the digest")
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

// protobufBody encodes obj as kubectl sends a built-in type: protobuf.
func protobufBody(t *testing.T, obj runtime.Object) []byte {
	t.Helper()
	s := runtime.NewScheme()
	if err := rbacv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	enc := serializer.NewCodecFactory(s).EncoderForVersion(protobuf.NewSerializer(s, s), rbacv1.SchemeGroupVersion)
	b, err := runtime.Encode(enc, obj)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, protobufMagic) {
		t.Fatalf("not a protobuf body: %q", b[:8])
	}
	return b
}

// `kubectl create clusterrolebinding` sends protobuf, never JSON: found
// by the live kind run, which a JSON-only decode left unmeasured. The
// approver must see the same grant either way.
func TestAuthorityImpactReadsProtobuf(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, "", "", 200, &seen)
	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "agent-view"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacGroup, Kind: "ClusterRole", Name: "view"},
		Subjects: []rbacv1.Subject{{APIGroup: rbacGroup, Kind: "User", Name: "coding-agent"}, {Kind: "ServiceAccount", Name: "ci", Namespace: "demo"}}}
	a := rbacAction("create", "clusterrolebindings", "", "")
	i := e.assessMutation(context.Background(), a, protobufBody(t, crb))
	if !i.Measured || len(i.Effects) != 1 || i.Effects[0].Object != "rbac.authorization.k8s.io/ClusterRoleBinding//agent-view" ||
		i.Effects[0].Explanation != "binds ClusterRole/view to User coding-agent, ServiceAccount demo/ci" {
		t.Fatalf("impact = %+v", i)
	}
	json := e.assessMutation(context.Background(), a, []byte(`{"metadata":{"name":"agent-view"},"roleRef":{"kind":"ClusterRole","name":"view"},"subjects":[{"kind":"User","name":"coding-agent"},{"kind":"ServiceAccount","name":"ci","namespace":"demo"}]}`))
	if json.Digest() != i.Digest() {
		t.Error("the same grant digests differently as JSON and as protobuf")
	}
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "reader"}, Rules: []rbacv1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"pods"}}}}
	if i := e.assessMutation(context.Background(), rbacAction("create", "roles", "demo", ""), protobufBody(t, role)); !i.Measured || i.Effects[0].Explanation != "allows get on pods" {
		t.Errorf("role = %+v", i)
	}

	for name, body := range map[string][]byte{
		"a Role sent to clusterrolebindings": protobufBody(t, role),
		"a RoleBinding sent to clusterrolebindings": protobufBody(t, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "x"},
			RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "admin"}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "u"}}}),
		"generateName": protobufBody(t, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{GenerateName: "x-"},
			RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "admin"}}),
		"truncated":  protobufBody(t, crb)[:20],
		"magic only": []byte("k8s\x00"),
	} {
		i := e.assessMutation(context.Background(), a, body)
		if i.Class != ClassAuthority || i.Measured {
			t.Errorf("%s: impact = %+v, want unmeasured AUTHORITY", name, i)
		}
	}
	if len(seen) != 0 {
		t.Error("an authority grant was sent to the API server during scoring")
	}
}
