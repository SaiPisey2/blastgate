package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/normalize"
	"github.com/SaiPisey2/blastgate/internal/store"
)

const testKey = "3f9a1c07d24be85f6a0913c7e2d84b5f70a6c31e9d28f4b1"

// cliEnv is a data dir and signing key, the environment the local
// commands (approve, deny, approvals, replay, audit) run with.
func cliEnv(t *testing.T) (string, func(string) string) {
	t.Helper()
	dir := t.TempDir()
	m := map[string]string{"BLASTGATE_DATA_DIR": dir, "BLASTGATE_SIGNING_KEY": testKey}
	return dir, func(k string) string { return m[k] }
}

// withStore opens the same database the commands will, for seeding and
// checking, and closes it before the command under test runs.
func withStore(t *testing.T, dir string, f func(*store.Store)) {
	t.Helper()
	st, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	f(st)
}

func seedPending(t *testing.T, dir string) string {
	t.Helper()
	id := "0123456789abcdef0123456789abcdef"
	imp, _ := json.Marshal(engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1, Undo: "none"})
	act, _ := json.Marshal(normalize.Action{Verb: "delete", Resource: "persistentvolumeclaims", Namespace: "demo", Name: "data"})
	withStore(t, dir, func(st *store.Store) {
		now := time.Now().UTC()
		if err := st.CreateApproval(context.Background(), store.Approval{
			ID: id, Session: "sess-1", Human: "alice", Agent: "coding-agent",
			RequestDigest: "req", ImpactDigest: "imp", ActionJSON: act, ImpactJSON: imp,
			Rule: "data-destruction", Status: "pending", Created: now, Expires: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	})
	return id
}

func runCLI(env func(string) string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, env, &out, &errb)
	return code, out.String(), errb.String()
}

func TestApproveNeedsBy(t *testing.T) {
	dir, env := cliEnv(t)
	id := seedPending(t, dir)
	if code, _, errs := runCLI(env, "approve", id); code != 2 {
		t.Errorf("exit = %d, want 2: %s", code, errs)
	}
	// An approver name that could not be a human name is refused too: it
	// lands in the audit trail beside the humans it is compared with.
	for _, by := range []string{"", "bob smith", "bob\x1b[2J", strings.Repeat("b", 254)} {
		if code, _, errs := runCLI(env, "approve", id, "--by", by); code != 2 {
			t.Errorf("--by %q: exit = %d, want 2: %s", by, code, errs)
		}
	}
	withStore(t, dir, func(st *store.Store) {
		a, err := st.ApprovalByID(context.Background(), id)
		if err != nil || a.Status != "pending" {
			t.Errorf("approval = %+v, %v; a refused approve must leave it pending", a, err)
		}
	})
}

func TestApproveUnknownIDIsRefused(t *testing.T) {
	_, env := cliEnv(t)
	if code, _, errs := runCLI(env, "approve", "ffffffffffffffffffffffffffffffff", "--by", "bob"); code != 2 {
		t.Errorf("exit = %d, want 2: %s", code, errs)
	}
}

func TestApproveThenApprovalsShowsApproved(t *testing.T) {
	dir, env := cliEnv(t)
	id := seedPending(t, dir)
	if code, _, errs := runCLI(env, "approve", id, "--by", "bob"); code != 0 {
		t.Fatalf("approve exit = %d: %s", code, errs)
	}
	withStore(t, dir, func(st *store.Store) {
		a, err := st.ApprovalByID(context.Background(), id)
		if err != nil || a.Status != "approved" || a.DecidedBy != "bob" || a.Token == "" {
			t.Errorf("approval = %+v, %v", a, err)
		}
		// The token lifetime is BLASTGATE_APPROVAL_TTL's default, 15m.
		if d := time.Until(a.Expires); d < 14*time.Minute || d > 16*time.Minute {
			t.Errorf("token expires in %v, want about 15m", d)
		}
	})
	code, out, errs := runCLI(env, "approvals")
	if code != 0 {
		t.Fatalf("approvals exit = %d: %s", code, errs)
	}
	for _, want := range []string{"ID", "SUMMARY", id, "alice", "coding-agent", "data-destruction", "approved", "1 volume with data destroyed"} {
		if !strings.Contains(out, want) {
			t.Errorf("approvals output lacks %q:\n%s", want, out)
		}
	}
	// Approving twice is a wrong-state refusal, not an operational error.
	if code, _, errs := runCLI(env, "approve", id, "--by", "bob"); code != 2 {
		t.Errorf("second approve exit = %d, want 2: %s", code, errs)
	}
	// --status filters.
	if _, out, _ := runCLI(env, "approvals", "--status", "pending"); strings.Contains(out, id) {
		t.Errorf("--status pending listed an approved approval:\n%s", out)
	}
}

func TestDenyWorks(t *testing.T) {
	dir, env := cliEnv(t)
	id := seedPending(t, dir)
	if code, _, errs := runCLI(env, "deny", "--by", "bob", id); code != 0 {
		t.Fatalf("deny exit = %d: %s", code, errs)
	}
	withStore(t, dir, func(st *store.Store) {
		a, err := st.ApprovalByID(context.Background(), id)
		if err != nil || a.Status != "denied" || a.DecidedBy != "bob" || a.Token != "" {
			t.Errorf("approval = %+v, %v", a, err)
		}
	})
	if code, _, _ := runCLI(env, "approve", id, "--by", "bob"); code != 2 {
		t.Errorf("approving a denied approval: exit = %d, want 2", code)
	}
	if code, _, _ := runCLI(env, "deny", id); code != 2 {
		t.Errorf("deny without --by: exit = %d, want 2", code)
	}
}

func decisionRow(at time.Time, id string, a normalize.Action, i engine.Impact, labels map[string]string, rule, decision string) store.AuditRow {
	act, _ := json.Marshal(a)
	imp, _ := json.Marshal(i)
	lab, _ := json.Marshal(labels)
	return store.AuditRow{
		At: at, Kind: "decision", RequestID: id, Session: "sess-1", Human: "alice", Agent: "coding-agent",
		Verb: a.Verb, Resource: a.Resource, Namespace: a.Namespace, Name: a.Name,
		ActionJSON: act, ImpactJSON: imp, LabelsJSON: lab,
		Class: i.Class, Measured: i.Measured, Rule: rule, Decision: decision,
	}
}

// seedDecisions writes one TERMINAL delete the default policy held and
// one REVERSIBLE patch it allowed, whose namespace labels were unknown.
func seedDecisions(t *testing.T, dir string) {
	t.Helper()
	now := time.Now().UTC()
	withStore(t, dir, func(st *store.Store) {
		for _, r := range []store.AuditRow{
			decisionRow(now.Add(-2*time.Minute), "r1",
				normalize.Action{Verb: "delete", Resource: "persistentvolumeclaims", Namespace: "demo", Name: "data"},
				engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1, Undo: "none"},
				map[string]string{}, "data-destruction", "hold"),
			decisionRow(now.Add(-time.Minute), "r2",
				normalize.Action{Verb: "patch", Resource: "configmaps", Namespace: "demo", Name: "settings"},
				engine.Impact{Class: engine.ClassReversible, Measured: true, Undo: "patch"},
				nil, "safe", "allow"),
			{At: now, Kind: "result", RequestID: "r2", Status: 200, Outcome: "ok", Rule: "safe", Decision: "allow"},
		} {
			if err := st.AppendAudit(context.Background(), r); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func writePolicy(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// allowEverything still holds the unmeasured: policy.Load refuses
// `unmeasured: allow` (ruling P1-R12).
const allowEverything = `rules:
  - name: everything
    when: "true"
    then: allow
default: allow
unmeasured: hold
`

func TestReplayCountsChanges(t *testing.T) {
	dir, env := cliEnv(t)
	seedDecisions(t, dir)
	code, out, errs := runCLI(env, "replay", "--policy", writePolicy(t, allowEverything))
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, errs)
	}
	if !strings.Contains(out, "2 decisions re-evaluated; 1 would change") {
		t.Errorf("output:\n%s", out)
	}
	if !strings.Contains(out, "data-destruction→everything hold→allow delete persistentvolumeclaims demo/data") {
		t.Errorf("no change line for the held delete:\n%s", out)
	}
	if strings.Contains(out, "settings") {
		t.Errorf("an unchanged decision was listed as a change:\n%s", out)
	}
}

// Stored labels of JSON null are "unknown", and must replay as unknown: a
// rule reading them errors and holds, as it did live. Replaying them as
// "no labels" would report a hold as an allow.
func TestReplayPassesUnknownLabelsAsUnknown(t *testing.T) {
	dir, env := cliEnv(t)
	seedDecisions(t, dir)
	p := writePolicy(t, `rules:
  - name: prod-is-held
    when: '"env" in ns.labels && ns.labels.env == "prod"'
    then: hold
default: allow
unmeasured: hold
`)
	code, out, errs := runCLI(env, "replay", "--policy", p)
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, errs)
	}
	// r1's labels are known and empty: the rule is false, so it moves from
	// hold to allow. r2's are unknown: the rule errors and holds. Were r2
	// replayed with empty labels it too would allow, and not change.
	if !strings.Contains(out, "2 decisions re-evaluated; 2 would change") ||
		!strings.Contains(out, "safe→error:prod-is-held allow→hold patch configmaps demo/settings") {
		t.Errorf("output:\n%s", out)
	}
}

func TestReplayHonoursSince(t *testing.T) {
	dir, env := cliEnv(t)
	seedDecisions(t, dir)
	_, out, _ := runCLI(env, "replay", "--policy", writePolicy(t, allowEverything), "--since", "90s")
	if !strings.Contains(out, "1 decisions re-evaluated; 0 would change") {
		t.Errorf("output:\n%s", out)
	}
}

func TestReplayRefusesABadPolicy(t *testing.T) {
	dir, env := cliEnv(t)
	seedDecisions(t, dir)
	for name, p := range map[string]string{
		"unparseable":      writePolicy(t, "rules: [nope"),
		"unmeasured allow": writePolicy(t, strings.Replace(allowEverything, "unmeasured: hold", "unmeasured: allow", 1)),
		"missing":          filepath.Join(t.TempDir(), "absent.yaml"),
	} {
		if code, _, errs := runCLI(env, "replay", "--policy", p); code != 2 {
			t.Errorf("%s: exit = %d, want 2: %s", name, code, errs)
		}
	}
	if code, _, _ := runCLI(env, "replay"); code != 2 {
		t.Errorf("no --policy: exit = %d, want 2", code)
	}
}

func TestAuditExportIsJSONL(t *testing.T) {
	dir, env := cliEnv(t)
	seedDecisions(t, dir)
	code, out, errs := runCLI(env, "audit", "export")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, errs)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d lines, want 3:\n%s", len(lines), out)
	}
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("line is not JSON: %v\n%s", err, l)
		}
		if _, ok := m["decision"]; !ok {
			t.Errorf("no decision field: %s", l)
		}
		if _, ok := m["rule"]; !ok {
			t.Errorf("no rule field: %s", l)
		}
	}
	var first map[string]any
	json.Unmarshal([]byte(lines[0]), &first)
	if imp, ok := first["impact"].(map[string]any); !ok || imp["class"] != "TERMINAL" {
		t.Errorf("impact not exported as an object: %s", lines[0])
	}
	if code, _, _ := runCLI(env, "audit", "frobnicate"); code != 2 {
		t.Errorf("unknown audit command: exit = %d, want 2", code)
	}
}

// serveEnv is a complete, valid serve environment -- a real upstream
// kubeconfig included -- so a refusal test fails only on the one setting
// it changes, not on a missing upstream that would also exit 2.
func serveEnv(t *testing.T, extra map[string]string) func(string) string {
	up := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(up.Close)
	m := map[string]string{
		"BLASTGATE_DATA_DIR":            t.TempDir(),
		"BLASTGATE_LISTEN":              freeAddr(t),
		"BLASTGATE_SIGNING_KEY":         testKey,
		"BLASTGATE_UPSTREAM_KUBECONFIG": writeUpstream(t, up),
	}
	for k, v := range extra {
		m[k] = v
	}
	return func(k string) string { return m[k] }
}

// refusalCtx bounds a serve that should have refused but started instead:
// it shuts down with exit 0 and the test fails, rather than hanging.
func refusalCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestServeRefusesABadPolicyFile(t *testing.T) {
	p := writePolicy(t, "rules: [nope")
	var errb syncBuf
	if code := serveCmd(refusalCtx(t), serveEnv(t, map[string]string{"BLASTGATE_POLICY": p}), &errb); code != 2 {
		t.Errorf("exit = %d, want 2: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), p) {
		t.Errorf("refusal does not name the file: %s", errb.String())
	}
}

func TestServeRefusesAHoldOver50s(t *testing.T) {
	var errb syncBuf
	if code := serveCmd(refusalCtx(t), serveEnv(t, map[string]string{"BLASTGATE_HOLD": "51s"}), &errb); code != 2 {
		t.Errorf("exit = %d, want 2: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "BLASTGATE_HOLD") {
		t.Errorf("refusal does not name BLASTGATE_HOLD: %s", errb.String())
	}
}

// TestAuditExportBytesAreStable pins the export's exact bytes, every
// field set, a column that is not JSON and one that is empty: the row
// type moved into internal/admin (shared with the UI feed), and a
// renamed tag, a reordered field or the feed's id leaking into the
// export would silently change what downstream readers of the JSONL get.
func TestAuditExportBytesAreStable(t *testing.T) {
	dir, env := cliEnv(t)
	withStore(t, dir, func(st *store.Store) {
		for _, r := range []store.AuditRow{
			{
				At: time.Date(2026, 1, 2, 3, 4, 5, 678e6, time.UTC), Kind: "decision", RequestID: "r1", Session: "0123456789abcdef",
				Human: "alice", Agent: "coding-agent", Source: "proxy", Verb: "delete", Group: "apps", Resource: "deployments",
				Subresource: "scale", Namespace: "demo", Name: "web", RequestDigest: "d1", ActionJSON: []byte(`{"verb":"delete"}`),
				ImpactJSON: []byte(`{"class":"TERMINAL"}`), LabelsJSON: []byte(`not json`), Class: "TERMINAL", Measured: true,
				Rule: "data-destruction", Decision: "hold", ApprovalID: "0123456789abcdef0123456789abcdef",
				Status: 403, Outcome: "held", LatencyMS: 12, Snapshot: "snap-1",
			},
			{At: time.Date(2026, 1, 2, 3, 4, 6, 0, time.UTC), Kind: "result", RequestID: "r1", Status: 200, Outcome: "ok"},
		} {
			if err := st.AppendAudit(context.Background(), r); err != nil {
				t.Fatal(err)
			}
		}
	})
	code, out, errs := runCLI(env, "audit", "export", "--since", "1000000h")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, errs)
	}
	const want = `{"at":"2026-01-02T03:04:05.678Z","kind":"decision","request_id":"r1","session":"0123456789abcdef","human":"alice","agent":"coding-agent","source":"proxy","verb":"delete","group":"apps","resource":"deployments","subresource":"scale","namespace":"demo","name":"web","request_digest":"d1","class":"TERMINAL","measured":true,"rule":"data-destruction","decision":"hold","approval_id":"0123456789abcdef0123456789abcdef","status":403,"outcome":"held","latency_ms":12,"snapshot":"snap-1","action":{"verb":"delete"},"impact":{"class":"TERMINAL"},"labels":"not json"}
{"at":"2026-01-02T03:04:06Z","kind":"result","request_id":"r1","session":"","human":"","agent":"","source":"","verb":"","group":"","resource":"","subresource":"","namespace":"","name":"","request_digest":"","class":"","measured":false,"rule":"","decision":"","approval_id":"","status":200,"outcome":"ok","latency_ms":0,"snapshot":""}
`
	if out != want {
		t.Errorf("export bytes changed:\ngot:\n%s\nwant:\n%s", out, want)
	}
}
