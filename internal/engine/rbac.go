package engine

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"unicode"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	k8sjson "sigs.k8s.io/json"

	"github.com/SaiPisey2/blastgate/internal/normalize"
)

const rbacGroup = "rbac.authorization.k8s.io"

// GrantUnknown is the explanation of an access grant whose object was
// not read: the console shows nothing more specific for it.
const GrantUnknown = "changes who may act in the cluster"

// rbacKinds are the RBAC resources whose objects authorityImpact reads,
// by resource, with whether they are namespaced.
var rbacKinds = map[string]struct {
	kind       string
	namespaced bool
}{
	"rolebindings":        {"RoleBinding", true},
	"clusterrolebindings": {"ClusterRoleBinding", false},
	"roles":               {"Role", true},
	"clusterroles":        {"ClusterRole", false},
}

// Caps on what an approver is shown. The strings come from the agent's
// request body, so they are bounded before they reach the impact, the
// audit and the console: a name is at most a Kubernetes name, and the
// whole explanation at most a few lines.
const (
	maxRBACString      = 253
	maxRBACExplanation = 512
	maxRBACSubjects    = 8
	maxRBACRules       = 6
	maxRBACList        = 6
)

// rbacObject is the part of an RBAC object an approver needs to see.
type rbacObject struct {
	Metadata struct {
		Name         string `json:"name"`
		GenerateName string `json:"generateName"`
		Namespace    string `json:"namespace"`
	} `json:"metadata"`
	RoleRef *struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"roleRef"`
	Subjects []struct {
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"subjects"`
	Rules []struct {
		Verbs           []string `json:"verbs"`
		Resources       []string `json:"resources"`
		NonResourceURLs []string `json:"nonResourceURLs"`
	} `json:"rules"`
	AggregationRule *struct{} `json:"aggregationRule"`
}

// authorityImpact is the impact of a write that changes who may act. It
// is never sent to the API server while scoring (a dry-run would say only
// that the grant is valid), so for an RBAC create or update it reads the
// request body itself -- the bytes the request digest, and so the token,
// already bind -- and names what is granted: the binding's role and
// subjects, or the role's rules. The explanation is inside the impact
// digest, so the approval covers exactly what the approver was shown.
//
// The class is AUTHORITY whatever happens here: what cannot be read is
// unmeasured (Measured false, the console's typed confirmation), never a
// different class, because any other class would let one person approve
// an access grant.
func authorityImpact(a normalize.Action, body []byte) Impact {
	generic := Effect{Kind: "grants", Object: resourceRef(a), Explanation: GrantUnknown}
	rk, ok := rbacKinds[a.Resource]
	if a.Group != rbacGroup || a.Subresource != "" || !ok {
		// A service-account token or a CSR approval: there is no object
		// to read that says more than the resource does.
		return Impact{Class: ClassAuthority, Measured: true, Undo: "none", Effects: []Effect{generic}}
	}
	unmeasured := func(reason string) Impact {
		return Impact{Class: ClassAuthority, Measured: false, Reason: reason, Undo: "none", Effects: []Effect{generic}}
	}
	if a.Verb != "create" && a.Verb != "update" {
		// A patch is only a difference; what it grants depends on the
		// live object it is applied to, which is not read here.
		return unmeasured("an RBAC " + a.Verb + " is not decoded: what it grants is not shown")
	}
	var obj rbacObject
	if bytes.HasPrefix(body, protobufMagic) {
		// kubectl sends built-in types as protobuf: `kubectl create
		// clusterrolebinding` never sends JSON at all.
		o, ok := decodeRBACProtobuf(body, rk.kind)
		if !ok {
			return unmeasured("the RBAC object could not be read")
		}
		obj = o
	} else if err := k8sjson.UnmarshalCaseSensitivePreserveInts(body, &obj); err != nil {
		// Case-sensitive, as the API server decodes: encoding/json would
		// also take "Subjects" for "subjects", so a body carrying both
		// could show the approver one list while the server stores the
		// other.
		return unmeasured("the RBAC object could not be read as JSON")
	}
	name := cleanRBAC(obj.Metadata.Name)
	switch {
	case name == "" || name != obj.Metadata.Name:
		// generateName, no name, or a name that is not printable: the
		// object the approver would be shown is not the one the server
		// names.
		return unmeasured("the RBAC object has no name blastgate can show")
	case a.Name != "" && a.Name != obj.Metadata.Name:
		return unmeasured("the RBAC object's name does not match the request path")
	case obj.Metadata.Namespace != "" && obj.Metadata.Namespace != a.Namespace:
		return unmeasured("the RBAC object's namespace does not match the request path")
	case rk.namespaced && a.Namespace == "":
		return unmeasured("a namespaced RBAC object without a namespace")
	}
	ns := ""
	if rk.namespaced {
		ns = a.Namespace
	}
	var expl string
	if strings.HasSuffix(rk.kind, "Binding") {
		if obj.RoleRef == nil || cleanRBAC(obj.RoleRef.Name) == "" || cleanRBAC(obj.RoleRef.Kind) == "" {
			return unmeasured("the binding names no role")
		}
		expl = "binds " + cleanRBAC(obj.RoleRef.Kind) + "/" + cleanRBAC(obj.RoleRef.Name) + " to " + subjectsText(obj)
	} else {
		expl = rulesText(obj)
	}
	return Impact{Class: ClassAuthority, Measured: true, Undo: "none", Effects: []Effect{{
		Kind:        "grants",
		Object:      rbacGroup + "/" + rk.kind + "/" + ns + "/" + name,
		Explanation: clip(expl, maxRBACExplanation),
	}}}
}

func subjectsText(obj rbacObject) string {
	if len(obj.Subjects) == 0 {
		return "no subjects"
	}
	var parts []string
	for i, s := range obj.Subjects {
		if i == maxRBACSubjects {
			parts = append(parts, fmt.Sprintf("and %d more", len(obj.Subjects)-i))
			break
		}
		who := cleanRBAC(s.Name)
		if ns := cleanRBAC(s.Namespace); ns != "" {
			who = ns + "/" + who
		}
		parts = append(parts, cleanRBAC(s.Kind)+" "+who)
	}
	return strings.Join(parts, ", ")
}

func rulesText(obj rbacObject) string {
	if obj.AggregationRule != nil {
		// The rules of an aggregated ClusterRole are filled in by the
		// controller from other roles; the body's own rules are not them.
		return "aggregates the rules of other ClusterRoles"
	}
	if len(obj.Rules) == 0 {
		return "allows nothing"
	}
	var parts []string
	for i, r := range obj.Rules {
		if i == maxRBACRules {
			parts = append(parts, fmt.Sprintf("and %d more rules", len(obj.Rules)-i))
			break
		}
		on := append(append([]string(nil), r.Resources...), r.NonResourceURLs...)
		parts = append(parts, listText(r.Verbs)+" on "+listText(on))
	}
	return "allows " + strings.Join(parts, "; ")
}

// listText joins a capped, sorted, cleaned list: sorted so the same rule
// written in another order digests the same and reads the same.
func listText(l []string) string {
	if len(l) == 0 {
		return "nothing"
	}
	c := make([]string, 0, len(l))
	for _, s := range l {
		c = append(c, cleanRBAC(s))
	}
	sort.Strings(c)
	if len(c) > maxRBACList {
		c = append(c[:maxRBACList], fmt.Sprintf("and %d more", len(l)-maxRBACList))
	}
	return strings.Join(c, ",")
}

// unprintable is the rule blastgate applies to every name it did not
// choose: control, format (bidi overrides), line and paragraph
// separators, NBSP and private-use runes all fail unicode.IsPrint, and Cf
// is named too so the intent survives a change to IsPrint.
func unprintable(r rune) bool {
	return !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r)
}

// cleanRBAC drops unprintable runes and caps the length of one string
// from the request body. A bidi override in a subject name could
// otherwise make the approver read a different name than the one bound.
func cleanRBAC(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unprintable(r) {
			continue
		}
		if n == maxRBACString {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// clip caps s at n runes.
func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// protobufMagic starts every Kubernetes protobuf body.
var protobufMagic = []byte("k8s\x00")

// rbacDecoder decodes rbac.authorization.k8s.io/v1 objects and nothing
// else: a protobuf body of any other type is not an RBAC object.
var rbacDecoder = func() runtime.Decoder {
	s := runtime.NewScheme()
	if err := rbacv1.AddToScheme(s); err != nil {
		panic(err)
	}
	return serializer.NewCodecFactory(s).UniversalDeserializer()
}()

// decodeRBACProtobuf reads a protobuf RBAC body into the fields an
// approver is shown. The object must be the kind the path names: the
// server refuses any other, and showing it would show the wrong thing.
func decodeRBACProtobuf(body []byte, kind string) (rbacObject, bool) {
	o, _, err := rbacDecoder.Decode(body, nil, nil)
	if err != nil {
		return rbacObject{}, false
	}
	var out rbacObject
	set := func(name, generateName, namespace string) {
		out.Metadata.Name, out.Metadata.GenerateName, out.Metadata.Namespace = name, generateName, namespace
	}
	binding := func(ref rbacv1.RoleRef, subjects []rbacv1.Subject) {
		out.RoleRef = &struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		}{ref.Kind, ref.Name}
		for _, sj := range subjects {
			out.Subjects = append(out.Subjects, struct {
				Kind      string `json:"kind"`
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			}{sj.Kind, sj.Name, sj.Namespace})
		}
	}
	rules := func(rs []rbacv1.PolicyRule) {
		for _, r := range rs {
			out.Rules = append(out.Rules, struct {
				Verbs           []string `json:"verbs"`
				Resources       []string `json:"resources"`
				NonResourceURLs []string `json:"nonResourceURLs"`
			}{r.Verbs, r.Resources, r.NonResourceURLs})
		}
	}
	got := ""
	switch v := o.(type) {
	case *rbacv1.ClusterRoleBinding:
		got = "ClusterRoleBinding"
		set(v.Name, v.GenerateName, v.Namespace)
		binding(v.RoleRef, v.Subjects)
	case *rbacv1.RoleBinding:
		got = "RoleBinding"
		set(v.Name, v.GenerateName, v.Namespace)
		binding(v.RoleRef, v.Subjects)
	case *rbacv1.ClusterRole:
		got = "ClusterRole"
		set(v.Name, v.GenerateName, v.Namespace)
		rules(v.Rules)
		if v.AggregationRule != nil {
			out.AggregationRule = &struct{}{}
		}
	case *rbacv1.Role:
		got = "Role"
		set(v.Name, v.GenerateName, v.Namespace)
		rules(v.Rules)
	}
	return out, got == kind
}
