//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"
)

// The CSP the admin listener must send on everything it serves
// (P2-R25, task-6-carry.md).
const wantCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// approvalJSON is the part of an approval the scenarios read.
type approvalJSON struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Rule      string `json:"rule"`
	DecidedBy string `json:"decided_by"`
}

// dataClaim makes a claim on kind's local-path class (reclaim Delete) and
// a pod that mounts it, so it binds: deleting it destroys data, which is
// what the data-destruction rule holds. The fixture's own claim is gone
// by now (phase 1 deletes it), so each test that needs one makes its own.
func dataClaim(t *testing.T, name string) {
	t.Helper()
	f := writeTemp(t, fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: %[1]s, namespace: demo}
spec:
  accessModes: [ReadWriteOnce]
  resources: {requests: {storage: 16Mi}}
---
apiVersion: v1
kind: Pod
metadata: {name: %[1]s-user, namespace: demo}
spec:
  terminationGracePeriodSeconds: 0
  containers:
  - name: user
    image: registry.k8s.io/e2e-test-images/busybox:1.36.1-1
    command: [sh, -c, 'echo row > /data/table && exec sleep 2147483647']
    volumeMounts: [{name: data, mountPath: /data}]
    resources: {requests: {cpu: 5m, memory: 8Mi}}
  volumes:
  - name: data
    persistentVolumeClaim: {claimName: %[1]s}
`, name))
	t.Cleanup(func() {
		kubectl(t, adminKC, nil, "", "delete", "pod", name+"-user", "-n", "demo", "--ignore-not-found", "--wait=false")
		kubectl(t, adminKC, nil, "", "delete", "pvc", name, "-n", "demo", "--ignore-not-found", "--wait=false")
	})
	must(t)(kubectl(t, adminKC, nil, "", "apply", "-f", f))
	must(t)(kubectl(t, adminKC, nil, "", "-n", "demo", "wait", "--for=jsonpath={.status.phase}=Bound", "pvc/"+name, "--timeout=120s"))
}

// heldConfigMapDelete makes a configmap as the fixture admin and has
// alice delete it through blastgate. Deleting a ConfigMap is COMPENSABLE
// and the default policy holds it: the cheapest held write there is.
func heldConfigMapDelete(t *testing.T, kc, name string) string {
	t.Helper()
	t.Cleanup(func() { kubectl(t, adminKC, nil, "", "delete", "configmap", name, "-n", "demo", "--ignore-not-found") })
	must(t)(kubectl(t, adminKC, nil, "", "create", "configmap", name, "-n", "demo"))
	out, err := kubectl(t, kc, nil, "", "delete", "configmap", name, "-n", "demo")
	m := ticket.FindStringSubmatch(out)
	if err == nil || m == nil {
		t.Fatalf("configmap delete was not held with a ticket:\n%s", out)
	}
	return m[1]
}

func TestAdminRequiresLogin(t *testing.T) {
	g := start(t)
	jar, _ := cookiejar.New(nil)
	c := g.adminHTTP(t, true, jar)
	base := "https://" + g.value("BLASTGATE_ADMIN_LISTEN")
	res, err := c.Get(base + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("/api/me without a session: %d, want 401", res.StatusCode)
	}
	res, err = c.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Errorf("index.html: %d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if got := res.Header.Get("Content-Security-Policy"); got != wantCSP {
		t.Errorf("index.html CSP = %q, want %q", got, wantCSP)
	}
}

// The browser path end to end: the held request's ticket, approved by a
// signed-in approver through the API, releases kubectl's retry, and the
// decision carries the approver's name from their session.
func TestApproveFromTheAPIReleasesTheRetry(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	dataClaim(t, "e2e-api-claim")
	out, err := kubectl(t, kc, nil, "", "delete", "pvc", "e2e-api-claim", "-n", "demo", "--wait=false")
	m := ticket.FindStringSubmatch(out)
	if err == nil || m == nil || !strings.Contains(out, "data-destruction") {
		t.Fatalf("claim delete was not held by the data-destruction rule:\n%s", out)
	}
	a := g.admin(t)
	var ap approvalJSON
	if code := a.do(t, http.MethodPost, "/api/approvals/"+m[1]+"/approve", nil, &ap); code != http.StatusOK || ap.Status != "approved" {
		t.Fatalf("approve: %d, status %q", code, ap.Status)
	}
	must(t)(kubectl(t, kc, nil, "", "delete", "pvc", "e2e-api-claim", "-n", "demo", "--wait=false"))
	ap = approvalJSON{}
	if code := a.do(t, http.MethodGet, "/api/approvals/"+m[1], nil, &ap); code != http.StatusOK || ap.DecidedBy != "bob" {
		t.Errorf("approval after the retry: %d, decided_by %q, want bob", code, ap.DecidedBy)
	}
}

func TestDenyFromTheAPIRefusesTheRetry(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	id := heldConfigMapDelete(t, kc, "e2e-api-deny")
	var ap approvalJSON
	if code := g.admin(t).do(t, http.MethodPost, "/api/approvals/"+id+"/deny", nil, &ap); code != http.StatusOK || ap.Status != "denied" || ap.DecidedBy != "bob" {
		t.Fatalf("deny: %d, status %q, decided_by %q", code, ap.Status, ap.DecidedBy)
	}
	out, err := kubectl(t, kc, nil, "", "delete", "configmap", "e2e-api-deny", "-n", "demo")
	if err == nil || !strings.Contains(out, "denied") {
		t.Errorf("denied delete not refused:\n%s", out)
	}
	if _, err := kubectl(t, adminKC, nil, "", "get", "configmap", "e2e-api-deny", "-n", "demo"); err != nil {
		t.Errorf("the denied configmap is gone")
	}
}

func TestRevokeFromTheAPIStopsTheAgent(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	must(t)(kubectl(t, kc, nil, "", "get", "pods", "-n", "demo"))
	a := g.admin(t)
	var sessions []struct{ ID, Human, Agent, State string }
	if code := a.do(t, http.MethodGet, "/api/sessions", nil, &sessions); code != http.StatusOK || len(sessions) != 1 ||
		sessions[0].Human != "alice" || sessions[0].Agent != "e2e" || sessions[0].State != "active" {
		t.Fatalf("sessions: %d %+v", code, sessions)
	}
	var s struct{ State string }
	if code := a.do(t, http.MethodPost, "/api/sessions/"+sessions[0].ID+"/revoke", nil, &s); code != http.StatusOK || s.State != "revoked" {
		t.Fatalf("revoke: %d, state %q", code, s.State)
	}
	out, err := kubectl(t, kc, nil, "", "get", "pods", "-n", "demo")
	if err == nil || !strings.Contains(out, "Unauthorized") {
		t.Errorf("the revoked session still works:\n%s", out)
	}
}

// Replay from the API re-evaluates the audited decisions: the held delete
// is allowed under a policy with no rules.
func TestPolicyReplayFromTheAPI(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	heldConfigMapDelete(t, kc, "e2e-api-replay")
	var res struct {
		Evaluated, Changed int
		Changes            []struct {
			Resource       string `json:"resource"`
			Name           string `json:"name"`
			DecisionBefore string `json:"decision_before"`
			DecisionAfter  string `json:"decision_after"`
		}
	}
	body := map[string]any{"policy": "rules: []\ndefault: allow\nunmeasured: hold\n", "since_hours": 1}
	if code := g.admin(t).do(t, http.MethodPost, "/api/policy/replay", body, &res); code != http.StatusOK {
		t.Fatalf("replay: %d", code)
	}
	found := false
	for _, c := range res.Changes {
		if c.Resource == "configmaps" && c.Name == "e2e-api-replay" && c.DecisionBefore == "hold" && c.DecisionAfter == "allow" {
			found = true
		}
	}
	if res.Changed < 1 || !found {
		t.Errorf("replay did not report the held delete as allowed: %+v", res)
	}
}

type sseEvent struct{ name, data string }

// stream opens /api/stream and sends each event it reads to the channel,
// which closes when the stream ends.
func stream(t *testing.T, ctx context.Context, c *http.Client, base, wantProto string) <-chan sseEvent {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/stream", nil)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || res.Proto != wantProto {
		res.Body.Close()
		t.Fatalf("stream: %d over %s, want 200 over %s", res.StatusCode, res.Proto, wantProto)
	}
	ch := make(chan sseEvent, 64)
	go func() {
		defer close(ch)
		defer res.Body.Close()
		s := bufio.NewScanner(res.Body)
		var ev sseEvent
		for s.Scan() {
			switch l := s.Text(); {
			case l == "":
				if ev.name != "" {
					ch <- ev
				}
				ev = sseEvent{}
			case strings.HasPrefix(l, "event: "):
				ev.name = strings.TrimPrefix(l, "event: ")
			case strings.HasPrefix(l, "data: "):
				ev.data = strings.TrimPrefix(l, "data: ")
			}
		}
	}()
	return ch
}

// A held write reaches an open stream as an approvals event naming it,
// while kubectl is still being held. Over HTTP/1.1 and HTTP/2: a browser
// may speak either, and each flushes differently.
func TestStreamDeliversAHeldRequest(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	a := g.admin(t)
	for _, tc := range []struct {
		name  string
		http2 bool
		proto string
	}{{"http1.1", false, "HTTP/1.1"}, {"http2", true, "HTTP/2.0"}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c := g.adminHTTP(t, tc.http2, a.c.Jar)
			c.Timeout = 0 // the stream is meant to stay open; ctx bounds it
			events := stream(t, ctx, c, a.base, tc.proto)
			select {
			case ev, ok := <-events:
				if !ok || ev.name != "hello" {
					t.Fatalf("first event %+v, want hello", ev)
				}
			case <-ctx.Done():
				t.Fatal("no hello event")
			}
			name := "e2e-stream-" + tc.name
			t.Cleanup(func() { kubectl(t, adminKC, nil, "", "delete", "configmap", name, "-n", "demo", "--ignore-not-found") })
			must(t)(kubectl(t, adminKC, nil, "", "create", "configmap", name, "-n", "demo"))
			// kubectl is held for BLASTGATE_HOLD (3s) and then gets its
			// ticket; the approval is pending, and announced, from the
			// start of the hold.
			held := make(chan string, 1)
			go func() {
				out, _ := kubectl(t, kc, nil, "", "delete", "configmap", name, "-n", "demo")
				held <- out
			}()
			announced := map[string]bool{}
			id := ""
			for {
				if id != "" && announced[id] {
					return
				}
				select {
				case ev, ok := <-events:
					if !ok {
						t.Fatalf("stream ended before announcing the held request (announced %v)", announced)
					}
					if ev.name == "approvals" {
						for _, x := range approvalID.FindAllString(ev.data, -1) {
							announced[x] = true
						}
						if !announced[id] {
							t.Logf("approvals event %s", ev.data)
						}
					}
				case out := <-held:
					m := ticket.FindStringSubmatch(out)
					if m == nil {
						t.Fatalf("configmap delete was not held with a ticket:\n%s", out)
					}
					id = m[1]
				case <-ctx.Done():
					t.Fatalf("no approvals event named %q (announced %v)", id, announced)
				}
			}
		})
	}
}

// A write made with the cluster's own admin credentials never passed
// through blastgate: the webhook records it, with who made it.
func TestWriteWithOwnCredentialsIsABypass(t *testing.T) {
	g := startWithWebhook(t)
	t.Cleanup(func() {
		kubectl(t, adminKC, nil, "", "delete", "configmap", "bypass-x", "-n", "demo", "--ignore-not-found")
	})
	must(t)(kubectl(t, adminKC, nil, "", "create", "configmap", "bypass-x", "-n", "demo"))
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, r := range g.bypasses(t) {
			if r.Name == "bypass-x" && r.Namespace == "demo" && r.Resource == "configmaps" && r.Verb == "create" && !r.DryRun {
				if r.User != "kubernetes-admin" {
					t.Errorf("bypass row user %q, want kubernetes-admin", r.User)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no bypass row for configmap bypass-x within 10s: %+v", g.bypasses(t))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func TestWriteThroughBlastgateIsNotABypass(t *testing.T) {
	g := startWithWebhook(t)
	kc := g.session(t, "alice")
	pod := strings.TrimSpace(must(t)(kubectl(t, adminKC, nil, "", "get", "pods", "-n", "demo", "-l", "app=web", "-o", "jsonpath={.items[0].metadata.name}")))
	must(t)(kubectl(t, kc, nil, "", "annotate", "pod", pod, "-n", "demo", fmt.Sprintf("e2e-via-blastgate=%d", time.Now().UnixNano()), "--overwrite"))
	for _, r := range g.bypassBarrier(t) {
		if (r.Resource == "pods" && r.Name == pod) || r.User == "alice" {
			t.Errorf("a write through blastgate was recorded as a bypass: %+v", r)
		}
	}
}

// ignoredByDefault is whether user is one of Kubernetes' own components
// by the default ignore list the ruling fixes. Spelled out here, not
// read from the webhook package, so a change to the product's list shows
// up as a failure instead of moving the assertion with it.
func ignoredByDefault(user string) bool {
	for _, p := range []string{"system:node:", "system:kube-", "system:serviceaccount:kube-system:", "system:apiserver"} {
		if strings.HasPrefix(user, p) {
			return true
		}
	}
	return false
}

// A pod deleted through blastgate is recreated by its ReplicaSet,
// scheduled, and started: the ReplicaSet controller, the scheduler and
// the kubelet all write. None of them is a bypass.
func TestControllerWritesAreNotBypasses(t *testing.T) {
	t.Cleanup(func() {
		kubectl(t, adminKC, nil, "", "delete", "deployment", "e2e-ctl", "-n", "demo", "--ignore-not-found")
	})
	must(t)(kubectl(t, adminKC, nil, "", "create", "deployment", "e2e-ctl", "-n", "demo",
		"--image=registry.k8s.io/e2e-test-images/busybox:1.36.1-1", "--", "sleep", "2147483647"))
	must(t)(kubectl(t, adminKC, nil, "", "-n", "demo", "rollout", "status", "deploy/e2e-ctl", "--timeout=120s"))
	g := startWithWebhook(t)
	kc := g.session(t, "alice")
	pod := strings.TrimSpace(must(t)(kubectl(t, adminKC, nil, "", "get", "pods", "-n", "demo", "-l", "app=e2e-ctl", "-o", "jsonpath={.items[0].metadata.name}")))
	// No Service selects e2e-ctl, so its pod is REVERSIBLE and allowed.
	must(t)(kubectl(t, kc, nil, "", "delete", "pod", pod, "-n", "demo", "--wait=false"))
	replaced := false
	for i := 0; i < 120 && !replaced; i++ {
		out, _ := kubectl(t, adminKC, nil, "", "get", "pods", "-n", "demo", "-l", "app=e2e-ctl",
			"-o", `jsonpath={range .items[*]}{.metadata.name} {.status.containerStatuses[0].ready}{"\n"}{end}`)
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] != pod && f[1] == "true" {
				replaced = true
			}
		}
		if !replaced {
			time.Sleep(time.Second)
		}
	}
	if !replaced {
		t.Fatal("the ReplicaSet never replaced the deleted pod with a ready one")
	}
	for _, r := range g.bypassBarrier(t) {
		if ignoredByDefault(r.User) {
			t.Errorf("a control-plane write was recorded as a bypass: %+v", r)
		}
	}
}
