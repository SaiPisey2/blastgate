package store_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SaiPisey2/blastgate/internal/approval"
	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/normalize"
	"github.com/SaiPisey2/blastgate/internal/store"
	"github.com/SaiPisey2/blastgate/internal/upstream"
)

// What happens to access grants a v0.3.0 binary approved with one person
// when v0.4.0 takes over the database. A retry is re-scored before its
// token is checked (gate.recheck, gate.go), so the outcome depends on
// whether v0.4.0 measures the request the way v0.3.0 did:
//
//   - An RBAC write: v0.3.0 stored the generic "changes who may act"
//     effect; v0.4.0 names the binding. The fresh digest differs, the
//     approval is superseded, and the retry starts a new hold that needs
//     two people.
//   - A service-account token or CSR approval: measured as before, so
//     the old approval still releases until its token lapses.
//
// The README's upgrade note says exactly this; the test pins it with the
// real engine re-scoring each request, not a made-up impact.
func TestV030ApprovedAccessGrantsAfterTheUpgrade(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	now := t0.Add(2 * time.Minute)
	key := []byte("0c5e2f8a1b9d47e3a6f0c2d8b4e7a1f9c3d5e8b2a4f6c0d1")
	p := filepath.Join(t.TempDir(), "blastgate.db")

	// The engine never sends an authority write to the API server while
	// scoring; a counting server proves it stayed that way here.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	eng := engine.New(&upstream.Upstream{URL: u, Normal: http.DefaultTransport}, 5*time.Second)

	alice := normalize.Principal{Session: "s1", Human: "alice", Agent: "coding-agent"}
	rbac := normalize.Action{Verb: "create", Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings", Principal: alice}
	rbacBody := []byte(`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"agent-view"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"view"},"subjects":[{"kind":"User","name":"coding-agent"}]}`)
	token := normalize.Action{Verb: "create", Version: "v1", Resource: "serviceaccounts", Subresource: "token", Namespace: "demo", Name: "ci", Principal: alice}
	tokenBody := []byte(`{"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest","spec":{}}`)

	// v0.3.0's impact for every authority write: measured AUTHORITY with
	// one generic effect naming the resource.
	v030 := func(object string) engine.Impact {
		return engine.Impact{Class: engine.ClassAuthority, Measured: true, Undo: "none", Effects: []engine.Effect{{
			Kind: "grants", Object: object, Explanation: "changes who may act in the cluster"}}}
	}
	type row struct {
		id     string
		act    normalize.Action
		body   []byte
		imp    engine.Impact
		status string
	}
	rows := []row{
		{"a1", rbac, rbacBody, v030("rbac.authorization.k8s.io/clusterrolebindings//"), "approved"},
		{"a2", token, tokenBody, v030("serviceaccounts/token/demo/ci"), "approved"},
		{"a3", rbac, []byte(`{"metadata":{"name":"other"},"roleRef":{"kind":"ClusterRole","name":"edit"},"subjects":[{"kind":"User","name":"coding-agent"}]}`), v030("rbac.authorization.k8s.io/clusterrolebindings//"), "pending"},
	}
	svc := &approval.Service{Key: key, TokenTTL: 15 * time.Minute, PendingTTL: time.Hour, Now: func() time.Time { return now }}
	expires := t0.Add(16 * time.Minute)

	db, err := sql.Open("sqlite", "file:"+p+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for i, m := range store.V030Migrations {
		if _, err := db.ExecContext(ctx, m); err != nil {
			t.Fatalf("migration %d: %v", i+1, err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (?)`, i+1); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range rows {
		actJSON, _ := json.Marshal(r.act)
		impJSON, _ := json.Marshal(r.imp)
		a := store.Approval{ID: r.id, Session: "s1", Human: "alice", Agent: "coding-agent", RequestDigest: normalize.RequestDigest(r.act, r.body), ImpactDigest: r.imp.Digest()}
		nonce, tok, decided, by, exp := "", "", any(nil), "", t0.Add(time.Hour)
		if r.status == "approved" {
			nonce, by, decided, exp = "n-"+r.id, "bob", t0.Add(time.Minute).UnixMilli(), expires
			tok = svc.Token(a, nonce, expires)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO approvals (id, session_id, human, agent, request_digest, impact_digest,
			action_json, impact_json, rule, status, created_at, decided_at, decided_by, nonce, token, expires_at)
			VALUES (?,?,?,?,?,?,?,?,'grants-authority',?,?,?,?,?,?,?)`,
			a.ID, a.Session, a.Human, a.Agent, a.RequestDigest, a.ImpactDigest, actJSON, impJSON, r.status,
			t0.UnixMilli(), decided, by, nonce, tok, exp.UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	st, err := store.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc.Store = st

	// The retry, as the gate makes it: re-score, then check the approval
	// against the fresh digest.
	retry := func(r row) (approval.Outcome, engine.Impact) {
		t.Helper()
		imp := eng.Assess(ctx, r.act, r.body).Impact
		o, _, err := svc.Check(ctx, "s1", "alice", "coding-agent", normalize.RequestDigest(r.act, r.body), imp.Digest())
		if err != nil {
			t.Fatal(err)
		}
		return o, imp
	}

	o, fresh := retry(rows[0])
	if o != approval.Void {
		t.Fatalf("retry of a v0.3.0 single-approver RBAC grant = %v, want Void (superseded)", o)
	}
	if fresh.Class != engine.ClassAuthority || !fresh.Measured || fresh.Effects[0].Explanation != "binds ClusterRole/view to User coding-agent" {
		t.Fatalf("re-scored RBAC impact = %+v", fresh)
	}
	if a, _ := st.ApprovalByID(ctx, "a1"); a.Status != "superseded" {
		t.Fatalf("v0.3.0 RBAC approval is %s, want superseded", a.Status)
	}
	// The hold the retry starts in its place needs two people.
	b, _ := json.Marshal(fresh)
	if !approval.NeedsTwo(store.Approval{Status: "pending", ImpactJSON: b, ImpactDigest: fresh.Digest()}) {
		t.Error("the new hold for the re-scored RBAC grant does not need two approvers")
	}

	if o, _ := retry(rows[1]); o != approval.Release {
		t.Fatalf("retry of a v0.3.0 single-approver token request = %v, want Release (measured as before)", o)
	}
	if o, _ := retry(rows[1]); o != approval.None {
		t.Fatalf("second retry of the token request = %v, want None (spent)", o)
	}

	// A grant still pending at the upgrade needs two people, from the
	// browser.
	pend, err := st.ApprovalByID(ctx, "a3")
	if err != nil {
		t.Fatal(err)
	}
	if !approval.NeedsTwo(pend) {
		t.Error("a v0.3.0 pending access grant does not need two approvers after the upgrade")
	}
	if _, err := svc.Approve(ctx, "a3", approval.Approver{Name: "bob", Channel: "cli"}); err != approval.ErrChannelNotAllowed {
		t.Errorf("cli approve of a v0.3.0 pending grant: %v, want ErrChannelNotAllowed", err)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("re-scoring authority writes sent %d requests to the API server", n)
	}
}

// Past its expiry a v0.3.0 token releases nothing, even for a request
// v0.4.0 measures exactly as v0.3.0 did.
func TestV030TokenLapses(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	st, err := store.Open(filepath.Join(t.TempDir(), "bg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := t0.Add(16*time.Minute + time.Millisecond)
	svc := &approval.Service{Store: st, Key: []byte("0c5e2f8a1b9d47e3a6f0c2d8b4e7a1f9c3d5e8b2a4f6c0d1"), TokenTTL: 15 * time.Minute, Now: func() time.Time { return now }}
	imp := engine.Impact{Class: engine.ClassAuthority, Measured: true, Undo: "none"}
	impJSON, _ := json.Marshal(imp)
	a := store.Approval{ID: "a1", Session: "s1", Human: "alice", Agent: "coding-agent", RequestDigest: "rd", ImpactDigest: imp.Digest(),
		ActionJSON: []byte(`{}`), ImpactJSON: impJSON, Rule: "r", Status: "approved", Created: t0, Decided: t0, Expires: t0.Add(16 * time.Minute), DecidedBy: "bob", Nonce: "n"}
	a.Token = svc.Token(a, "n", a.Expires)
	if err := st.CreateApproval(ctx, a); err != nil {
		t.Fatal(err)
	}
	if o, _, err := svc.Check(ctx, "s1", "alice", "coding-agent", "rd", imp.Digest()); err != nil || o != approval.None {
		t.Fatalf("check of a lapsed token = %v, %v, want None", o, err)
	}
}
