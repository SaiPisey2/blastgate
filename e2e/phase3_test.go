//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// grantJSON is the part of an approval the two-person scenario reads.
type grantJSON struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	DecidedBy      string `json:"decided_by"`
	NeedsApprovers int    `json:"needs_approvers"`
	FirstApprover  string `json:"first_approver"`
}

// letAliceGrantView lets alice create cluster role bindings to the view
// role, and nothing more. The fixture gives her edit in demo, which holds
// no RBAC verbs; without this the grant, once two people release it,
// would be refused by the API server and the test could not tell that
// from blastgate never forwarding it.
func letAliceGrantView(t *testing.T) {
	t.Helper()
	f := writeTemp(t, `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: e2e-grant-view}
rules:
- apiGroups: [rbac.authorization.k8s.io]
  resources: [clusterrolebindings]
  verbs: [create, get, delete]
- apiGroups: [rbac.authorization.k8s.io]
  resources: [clusterroles]
  resourceNames: [view]
  verbs: [bind]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: e2e-grant-view}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: e2e-grant-view}
subjects:
- {apiGroup: rbac.authorization.k8s.io, kind: User, name: alice}
`)
	t.Cleanup(func() {
		kubectl(t, adminKC, nil, "", "delete", "-f", f, "--ignore-not-found")
	})
	must(t)(kubectl(t, adminKC, nil, "", "apply", "-f", f))
}

// An access grant needs two people, each with their own account and a
// recent sign-in: bob's approval alone leaves the agent held, bob cannot
// count twice, the CLI cannot add the second, and carol's approval
// releases the retry.
func TestAccessGrantNeedsTwoApprovers(t *testing.T) {
	letAliceGrantView(t)
	g := start(t)
	kc := g.session(t, "alice")
	const grant = "e2e-two-person"
	t.Cleanup(func() {
		kubectl(t, adminKC, nil, "", "delete", "clusterrolebinding", grant, "--ignore-not-found")
	})
	create := []string{"create", "clusterrolebinding", grant, "--clusterrole=view", "--user=coding-agent"}

	out, err := kubectl(t, kc, nil, "", create...)
	m := ticket.FindStringSubmatch(out)
	if err == nil || m == nil || !strings.Contains(out, "grants-authority") {
		t.Fatalf("the cluster role binding was not held by the grants-authority rule:\n%s", out)
	}
	id := m[1]

	bob := g.admin(t)
	var ap grantJSON
	if code := bob.do(t, http.MethodPost, "/api/approvals/"+id+"/approve", nil, &ap); code != http.StatusOK ||
		ap.Status != "partially_approved" || ap.FirstApprover != "bob" || ap.NeedsApprovers != 2 {
		t.Fatalf("bob's approval: %d %+v, want 200 partially_approved, first approver bob, needs 2", code, ap)
	}

	// One person's yes releases nothing: the retry waits out the hold and
	// gets the same ticket back.
	out, err = kubectl(t, kc, nil, "", create...)
	if m := ticket.FindStringSubmatch(out); err == nil || m == nil || m[1] != id {
		t.Fatalf("the retry after one approval was not held on the same ticket %s:\n%s", id, out)
	}
	if _, err := kubectl(t, adminKC, nil, "", "get", "clusterrolebinding", grant); err == nil {
		t.Fatal("the grant exists after one approval")
	}

	if code, msg := bob.refusal(t, http.MethodPost, "/api/approvals/"+id+"/approve"); code != http.StatusConflict ||
		msg != "you already approved this; it needs a second person" {
		t.Errorf("bob approving twice: %d %q, want 409 with the fixed text", code, msg)
	}

	// The CLI is a channel anyone with a shell on the host can use under
	// any name, so it can never be the second person.
	if out, err := g.run(t, "approve", id, "--by", "carol"); err == nil ||
		!strings.Contains(err.Error(), "access grants need two approvers in the browser") {
		t.Errorf("CLI approval of an access grant was not refused: %v\n%s", err, out)
	}

	carol := g.approver(t, "carol")
	ap = grantJSON{}
	if code := carol.do(t, http.MethodPost, "/api/approvals/"+id+"/approve", nil, &ap); code != http.StatusOK ||
		ap.Status != "approved" || ap.DecidedBy != "carol" || ap.FirstApprover != "bob" {
		t.Fatalf("carol's approval: %d %+v, want 200 approved, decided by carol, first approver bob", code, ap)
	}

	must(t)(kubectl(t, kc, nil, "", create...))
	must(t)(kubectl(t, adminKC, nil, "", "get", "clusterrolebinding", grant))
}

// An approver linked to a human can never approve that human's request,
// whatever name the approver signs in under; deny stays open to them.
func TestSelfApprovalIsRefused(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	id := heldConfigMapDelete(t, kc, "e2e-self-approval")
	dave := g.approver(t, "dave", "alice")
	if code, msg := dave.refusal(t, http.MethodPost, "/api/approvals/"+id+"/approve"); code != http.StatusForbidden ||
		msg != "you can't approve a request made on your behalf" {
		t.Fatalf("dave (linked to alice) approving alice's request: %d %q, want 403 with the fixed text", code, msg)
	}
	out, err := kubectl(t, kc, nil, "", "delete", "configmap", "e2e-self-approval", "-n", "demo")
	if m := ticket.FindStringSubmatch(out); err == nil || m == nil || m[1] != id {
		t.Fatalf("the retry after a refused self-approval was not held on ticket %s:\n%s", id, out)
	}
	var ap approvalJSON
	if code := dave.do(t, http.MethodPost, "/api/approvals/"+id+"/deny", nil, &ap); code != http.StatusOK || ap.Status != "denied" || ap.DecidedBy != "dave" {
		t.Errorf("dave's deny: %d %+v, want 200 denied by dave", code, ap)
	}
}

// The console says which cluster a decision lands on. Unset, that is the
// upstream kubeconfig's current context; BLASTGATE_CLUSTER_NAME overrides
// it. Both /api/me and the login answer carry it.
func TestClusterNameInMe(t *testing.T) {
	want := strings.TrimSpace(must(t)(kubectl(t, upstreamKC, nil, "", "config", "current-context")))
	if want == "" {
		t.Fatal("the upstream kubeconfig has no current context")
	}
	named := fmt.Sprintf("e2e-cluster-%d", time.Now().UnixNano()%1000)
	for _, tc := range []struct {
		name  string
		extra []string
		want  string
	}{
		{"from the upstream kubeconfig", nil, want},
		{"from BLASTGATE_CLUSTER_NAME", []string{"BLASTGATE_CLUSTER_NAME=" + named}, named},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := start(t, tc.extra...)
			a := g.admin(t)
			if a.loginCluster != tc.want {
				t.Errorf("login cluster = %q, want %q", a.loginCluster, tc.want)
			}
			var me struct{ Name, Cluster string }
			if code := a.do(t, http.MethodGet, "/api/me", nil, &me); code != http.StatusOK || me.Name != "bob" || me.Cluster != tc.want {
				t.Errorf("/api/me: %d %+v, want bob on %q", code, me, tc.want)
			}
		})
	}
}
