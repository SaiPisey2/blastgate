package engine

import (
	"context"
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/SaiPisey2/sounding/pkg/disruption"
	"github.com/SaiPisey2/sounding/pkg/model"

	"github.com/SaiPisey2/blastgate/internal/normalize"
)

// RealImpacts are impacts produced by the engine's own scoring paths,
// one or more per class, with every optional field some path fills (an
// effect explanation, endpoints, budgets, the SQL flag, a dry-run
// refusal), for the round-trip test in package engine_test, which needs
// the approval and store packages.
func RealImpacts(t *testing.T) map[string]Impact {
	t.Helper()
	ctx := context.Background()
	out := map[string]Impact{}
	var seen []*http.Request

	e := apiServer(t, `{"kind":"ConfigMap"}`, `{"kind":"Status","code":403}`, 403, &seen)
	e.look = &fakeLook{}
	out["read: dry-run refused"] = e.assessMutation(ctx, normalize.Action{Verb: "update", Version: "v1", Resource: "configmaps", Namespace: "demo", Name: "c", Principal: alice}, []byte(`{}`))

	e = apiServer(t, "", `{"kind":"ConfigMap","metadata":{"name":"c"}}`, 200, &seen)
	// Through Assess, as the gate scores: it sets Elapsed, which the
	// digest must ignore and the stored JSON does not carry.
	out["reversible: create"] = e.Assess(ctx, normalize.Action{Verb: "create", Version: "v1", Resource: "configmaps", Namespace: "demo", Principal: alice}, []byte(`{"metadata":{"name":"c"}}`)).Impact
	if out["reversible: create"].Elapsed == 0 {
		t.Fatal("Assess left Elapsed unset")
	}

	e = apiServer(t, deployment(3, `{"app":"web"}`), deployment(0, `{"app":"web"}`), 200, &seen)
	e.look = &fakeLook{report: disruption.Report{Services: []disruption.Service{{Name: "web", Ready: 3, Left: 0}}, Budgets: []disruption.Budget{{Name: "web-pdb", Healthy: 3, Desired: 2, Left: 0}}}}
	out["reversible: scale down"] = e.assessMutation(ctx, normalize.Action{Verb: "patch", Group: "apps", Version: "v1", Resource: "deployments", Namespace: "demo", Name: "web", PatchType: "application/merge-patch+json", Principal: alice}, []byte(`{"spec":{"replicas":0}}`))

	e = apiServer(t, deployment(1, `{"app":"web"}`), deployment(1, `{"app":"web2"}`), 200, &seen)
	e.look = &fakeLook{svcs: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "web"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "web"}}}}}
	out["reversible: relabel"] = e.assessMutation(ctx, normalize.Action{Verb: "update", Group: "apps", Version: "v1", Resource: "deployments", Namespace: "demo", Name: "web", Principal: alice}, []byte(deployment(1, `{"app":"web2"}`)))

	out["compensable: delete"] = fromFinding(finding(model.ClassCompensable, eff("destroys", "Deployment", "web"), eff("destroys", "Pod", "web-1")),
		disruption.Report{Services: []disruption.Service{{Name: "web", Ready: 1, Left: 0}}})
	out["terminal: delete with data"] = fromFinding(finding(model.ClassTerminal, eff("destroys", "PersistentVolumeClaim", "data"), eff("destroys-data", "PersistentVolume", "pv-1"), eff("unknown-data-fate", "PersistentVolume", "pv-2")),
		disruption.Report{Budgets: []disruption.Budget{{Name: "db-pdb", Healthy: 1, Desired: 1, Left: 0}}})
	out["terminal: unmeasured"] = Unmeasured("verb deletecollection is not measured by this build")
	out["terminal: exec with sql"] = assessExec(normalize.Action{Verb: "create", Resource: "pods", Subresource: "exec", Query: map[string][]string{"command": {"psql", "-c", "drop table t"}}})

	out["authority: binding"] = e.Assess(ctx, normalize.Action{Verb: "create", Group: rbacGroup, Version: "v1", Resource: "clusterrolebindings", Principal: alice},
		[]byte(`{"metadata":{"name":"agent-view"},"roleRef":{"kind":"ClusterRole","name":"view"},"subjects":[{"kind":"User","name":"coding-agent"}]}`)).Impact
	out["authority: unmeasured"] = authorityImpact(normalize.Action{Verb: "patch", Group: rbacGroup, Version: "v1", Resource: "clusterrolebindings", Name: "x", Principal: alice}, []byte(`{}`))
	out["authority: token"] = authorityImpact(normalize.Action{Verb: "create", Version: "v1", Resource: "serviceaccounts", Subresource: "token", Namespace: "demo", Name: "ci", Principal: alice}, []byte(`{}`))
	return out
}
