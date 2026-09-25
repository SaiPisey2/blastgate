//go:build e2e

package e2e

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

var ticket = regexp.MustCompile(`held for approval ([0-9a-f]{32})`)

// waitForWeb waits until web has a ready pod again: later tests exec into
// deploy/web, and one that picks a pod still starting fails for a reason
// that has nothing to do with blastgate.
func waitForWeb(t *testing.T) {
	t.Helper()
	must(t)(kubectl(t, adminKC, nil, "", "-n", "demo", "rollout", "status", "deploy/web", "--timeout=120s"))
	must(t)(kubectl(t, adminKC, nil, "", "-n", "demo", "wait", "--for=condition=Ready", "pod", "-l", "app=web", "--timeout=120s"))
}

// A pod a ReplicaSet recreates is REVERSIBLE: the default policy's safe
// rule allows it without anyone being asked. db's pod, not web's: web has
// one replica behind a Service in a prod namespace, and deleting that pod
// leaves the Service with no backends until it is replaced -- which the
// default policy rightly holds.
func TestDeletingAControlledPodIsAllowed(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	pod := strings.TrimPrefix(strings.TrimSpace(must(t)(kubectl(t, kc, nil, "", "get", "pods", "-n", "demo", "-l", "app=db", "-o", "name"))), "pod/")
	must(t)(kubectl(t, kc, nil, "", "delete", "pod", pod, "-n", "demo", "--wait=false"))
}

// Deleting a claim whose volume is reclaimed with Delete destroys data:
// held with a ticket that names no object, released once by approval.
func TestDeletingADataClaimIsHeldThenReleasedByApproval(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	out, err := kubectl(t, kc, nil, "", "delete", "pvc", "data", "-n", "demo", "--wait=false")
	m := ticket.FindStringSubmatch(out)
	if err == nil || m == nil {
		t.Fatalf("delete was not held with a ticket:\n%s", out)
	}
	if strings.Contains(out, "\"data\"") {
		t.Errorf("ticket names the object:\n%s", out)
	}
	if !strings.Contains(out, "data-destruction") {
		t.Errorf("ticket does not name the data-destruction rule:\n%s", out)
	}
	if _, err := g.run(t, "approve", m[1], "--by", "bob"); err != nil {
		t.Fatal(err)
	}
	must(t)(kubectl(t, kc, nil, "", "delete", "pvc", "data", "-n", "demo", "--wait=false"))
	// The audit shows the approval that released it.
	exp, err := g.run(t, "audit", "export", "--since", "10m")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(exp, m[1]) {
		t.Errorf("audit export lacks the approval id")
	}
}

// An approval covers the impact the approver saw. A second Service
// selecting the same pods changes it, so the approved retry is held again
// under a new ticket that says why.
func TestApprovalIsVoidWhenImpactChanges(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	// Scaling the only backend of a prod Service to zero is held.
	out, err := kubectl(t, kc, nil, "", "scale", "deploy/web", "-n", "demo", "--replicas=0")
	m := ticket.FindStringSubmatch(out)
	if err == nil || m == nil {
		t.Fatalf("scale to zero not held:\n%s", out)
	}
	if _, err := g.run(t, "approve", m[1], "--by", "bob"); err != nil {
		t.Fatal(err)
	}
	// Change the impact: a second Service now selects the same pods.
	t.Cleanup(func() { kubectl(t, adminKC, nil, "", "delete", "service", "web-extra", "-n", "demo") })
	must(t)(kubectl(t, adminKC, nil, "", "create", "service", "clusterip", "web-extra", "-n", "demo", "--tcp=81:8080"))
	must(t)(kubectl(t, adminKC, nil, "", "set", "selector", "service/web-extra", "app=web", "-n", "demo"))
	out, err = kubectl(t, kc, nil, "", "scale", "deploy/web", "-n", "demo", "--replicas=0")
	m2 := ticket.FindStringSubmatch(out)
	if err == nil || m2 == nil || m2[1] == m[1] || !strings.Contains(out, "changed") {
		t.Fatalf("retry after the impact changed was not held again with a new ticket:\n%s", out)
	}
}

// Approved while the request is still held, the original command
// completes: the agent never sees a ticket. The hold is 10s here (ruling
// P1-R2): the gate polls every 500ms and each CLI call starts a process,
// which a 3s window leaves too little room for.
func TestApprovalWithinTheHoldWindowCompletesTheOriginalCommand(t *testing.T) {
	g := start(t, "BLASTGATE_HOLD=10s")
	kc := g.session(t, "alice")
	done := make(chan string, 1)
	go func() {
		out, _ := kubectl(t, kc, nil, "", "exec", "-n", "demo", "deploy/web", "--", "echo", "approved-inline")
		done <- out
	}()
	var id string
	for i := 0; i < 50 && id == ""; i++ {
		time.Sleep(100 * time.Millisecond)
		list, _ := g.run(t, "approvals", "--status", "pending")
		id = approvalID.FindString(list)
	}
	if id == "" {
		t.Fatal("no pending approval appeared")
	}
	if _, err := g.run(t, "approve", id, "--by", "bob"); err != nil {
		t.Fatal(err)
	}
	if out := <-done; !strings.Contains(out, "approved-inline") {
		t.Errorf("exec did not complete after inline approval:\n%s", out)
	}
}

// An exec running a database client is held by its own rule; once denied,
// its retries are refused outright rather than held again.
func TestDeniedExecStaysRefused(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	out, _ := kubectl(t, kc, nil, "", "exec", "-n", "demo", "deploy/web", "--", "psql", "-c", "drop table x")
	m := ticket.FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "exec-with-sql") {
		t.Fatalf("exec with sql not held by its rule:\n%s", out)
	}
	if _, err := g.run(t, "deny", m[1], "--by", "bob"); err != nil {
		t.Fatal(err)
	}
	out, err := kubectl(t, kc, nil, "", "exec", "-n", "demo", "deploy/web", "--", "psql", "-c", "drop table x")
	if err == nil || !strings.Contains(out, "denied") {
		t.Errorf("denied exec not refused:\n%s", out)
	}
}

// A server-side apply body is YAML; kubectl's retry must digest the same
// as the held request, or no approval could ever release it.
func TestHeldServerSideApplyMatchesItsApproval(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	t.Cleanup(func() {
		kubectl(t, adminKC, nil, "", "scale", "deploy/web", "-n", "demo", "--replicas=1")
		waitForWeb(t)
	})
	// The whole Deployment, as fixture/manifests/03-demo.yaml has it, with
	// replicas 0. A manifest of replicas alone works once: kubectl's first
	// server-side apply migrates ownership of every client-side-applied
	// field to its own manager, and applying the short manifest again would
	// ask to remove the selector and template, which the server refuses.
	f := writeTemp(t, `apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: demo}
spec:
  replicas: 0
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
      - name: web
        image: registry.k8s.io/e2e-test-images/busybox:1.36.1-1
        command: [sh, -c, 'mkdir -p /www && echo blastgate-ok > /www/index.html && echo started && exec httpd -f -p 8080 -h /www']
        ports: [{containerPort: 8080}]
        resources: {requests: {cpu: 5m, memory: 8Mi}}
`)
	out, err := kubectl(t, kc, nil, "", "apply", "--server-side", "--force-conflicts", "-f", f)
	m := ticket.FindStringSubmatch(out)
	if err == nil || m == nil {
		t.Fatalf("apply to zero not held:\n%s", out)
	}
	if _, err := g.run(t, "approve", m[1], "--by", "bob"); err != nil {
		t.Fatal(err)
	}
	must(t)(kubectl(t, kc, nil, "", "apply", "--server-side", "--force-conflicts", "-f", f))
}

// Replay re-evaluates the audited decisions under a candidate policy. The
// held claim delete is allowed under a policy with no rules, so at least
// one decision changes. unmeasured stays hold: a policy allowing the
// unmeasured is refused at load (ruling P1-R12).
func TestReplayReportsWhatANewPolicyWouldChange(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	kubectl(t, kc, nil, "", "delete", "pvc", "data", "-n", "demo", "--wait=false") // held, audited
	pol := writeTemp(t, "rules: []\ndefault: allow\nunmeasured: hold\n")
	out, err := g.run(t, "replay", "--policy", pol, "--since", "1h")
	if err != nil || !regexp.MustCompile(`\d+ decisions re-evaluated; [1-9]\d* would change`).MatchString(out) {
		t.Errorf("replay: %v\n%s", err, out)
	}
}
