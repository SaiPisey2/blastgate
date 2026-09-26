package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SaiPisey2/blastgate/internal/approval"
	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/normalize"
	"github.com/SaiPisey2/blastgate/internal/session"
	"github.com/SaiPisey2/blastgate/internal/store"
)

// countingStore counts every call the API or the approval service makes
// into the store, so a test can prove a refused id never reached it.
// Every method either interface needs is listed here explicitly: one
// left to the embedded *store.Store would be forwarded uncounted.
type countingStore struct {
	*store.Store
	n atomic.Int64
	// lastLimit is the limit the last list call handed the store, so a
	// test can see a clamp the result size alone would not show.
	lastLimit atomic.Int64

	mu sync.Mutex
	// onAuditSince runs inside AuditSinceLimit before the query, so a
	// test can hold a replay in flight.
	onAuditSince func()
	// onDecide runs once inside DecideApproval before it forwards, so a
	// test can make another decision win the race.
	onDecide func(ctx context.Context, id string)
	// onAuditAfter runs once inside AuditAfter before it forwards, so a
	// test can land rows between the stream's hello and its first poll.
	onAuditAfter func()
}

func (c *countingStore) hooks() (func(), func(context.Context, string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.onAuditSince, c.onDecide
}

func (c *countingStore) setHooks(audit func(), decide func(context.Context, string)) {
	c.mu.Lock()
	c.onAuditSince, c.onDecide = audit, decide
	c.mu.Unlock()
}

func (c *countingStore) AuditPage(ctx context.Context, f store.AuditFilter) ([]store.AuditRow, error) {
	c.n.Add(1)
	return c.Store.AuditPage(ctx, f)
}
func (c *countingStore) AuditSinceLimit(ctx context.Context, since time.Time, kind string, limit int) ([]store.AuditRow, error) {
	c.n.Add(1)
	if hook, _ := c.hooks(); hook != nil {
		hook()
	}
	return c.Store.AuditSinceLimit(ctx, since, kind, limit)
}
func (c *countingStore) AuditAfter(ctx context.Context, afterID int64, limit int) ([]store.AuditRow, error) {
	c.n.Add(1)
	c.mu.Lock()
	hook := c.onAuditAfter
	c.onAuditAfter = nil
	c.mu.Unlock()
	if hook != nil {
		hook()
	}
	return c.Store.AuditAfter(ctx, afterID, limit)
}
func (c *countingStore) ListApprovalsLimit(ctx context.Context, status string, limit int) ([]store.Approval, error) {
	c.n.Add(1)
	c.lastLimit.Store(int64(limit))
	return c.Store.ListApprovalsLimit(ctx, status, limit)
}
func (c *countingStore) ApprovalByID(ctx context.Context, id string) (store.Approval, error) {
	c.n.Add(1)
	return c.Store.ApprovalByID(ctx, id)
}
func (c *countingStore) ListSessions(ctx context.Context) ([]store.Session, error) {
	c.n.Add(1)
	return c.Store.ListSessions(ctx)
}
func (c *countingStore) RevokeSession(ctx context.Context, id string, at time.Time) error {
	c.n.Add(1)
	return c.Store.RevokeSession(ctx, id, at)
}
func (c *countingStore) BypassSince(ctx context.Context, since time.Time, limit int) ([]store.BypassRow, error) {
	c.n.Add(1)
	c.lastLimit.Store(int64(limit))
	return c.Store.BypassSince(ctx, since, limit)
}
func (c *countingStore) CreateApproval(ctx context.Context, a store.Approval) error {
	c.n.Add(1)
	return c.Store.CreateApproval(ctx, a)
}
func (c *countingStore) LatestApproval(ctx context.Context, sess, digest string) (store.Approval, error) {
	c.n.Add(1)
	return c.Store.LatestApproval(ctx, sess, digest)
}
func (c *countingStore) DecideApproval(ctx context.Context, id, status, by, nonce, token string, decided, expires time.Time) error {
	c.n.Add(1)
	c.mu.Lock()
	hook := c.onDecide
	c.onDecide = nil
	c.mu.Unlock()
	if hook != nil {
		hook(ctx, id)
	}
	return c.Store.DecideApproval(ctx, id, status, by, nonce, token, decided, expires)
}
func (c *countingStore) ConsumeApproval(ctx context.Context, id, nonce string, at time.Time) error {
	c.n.Add(1)
	return c.Store.ConsumeApproval(ctx, id, nonce, at)
}
func (c *countingStore) SetApprovalStatus(ctx context.Context, id, from, to string) error {
	c.n.Add(1)
	return c.Store.SetApprovalStatus(ctx, id, from, to)
}

type apiFixture struct {
	st     *store.Store
	dbPath string
	cs     *countingStore
	clock  *clock
	auth   *Auth
	svc    *approval.Service
	api    *api
	srv    *httptest.Server
	// hc, when set, is the client signIn and openStream use: a TLS or
	// HTTP/2 server needs a client that trusts it.
	hc *http.Client
}

func (f *apiFixture) httpClient() *http.Client {
	if f.hc != nil {
		return f.hc
	}
	return http.DefaultClient
}

const testPolicyText = "default: hold\nunmeasured: hold\n"

func newAPIFixture(t *testing.T) *apiFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blastgate.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &apiFixture{st: st, dbPath: path, cs: &countingStore{Store: st}, clock: &clock{t: t0}}
	log := slog.New(slog.DiscardHandler)
	f.auth = NewAuth(st, log)
	f.auth.Now = f.clock.Now
	f.svc = &approval.Service{Store: f.cs, Key: []byte("0123456789abcdef0123456789abcdef"),
		TokenTTL: 10 * time.Minute, PendingTTL: time.Hour, Now: f.clock.Now}
	mux := http.NewServeMux()
	f.api = routes(mux, f.auth, Deps{Store: st, Approvals: f.svc, PolicySource: "/etc/blastgate/policy.yaml",
		PolicyText: []byte(testPolicyText), Log: log}, f.cs)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// client is a signed-in browser: it logged in through /api/login and
// carries the cookie and the CSRF value it was given, as the UI does.
type client struct {
	f      *apiFixture
	cookie string
	csrf   string
	name   string
}

func (f *apiFixture) signIn(t *testing.T, name string) *client {
	t.Helper()
	tok, h := NewLoginToken()
	if err := f.st.CreateApprover(context.Background(), store.Approver{ID: "ap-" + name, Name: name, Created: f.clock.Now()}, h); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"token": tok})
	req, _ := http.NewRequest("POST", f.srv.URL+"/api/login", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	var out struct{ Name, CSRF string }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return &client{f: f, cookie: resp.Cookies()[0].Value, csrf: out.CSRF, name: out.Name}
}

// call sends one request. A nil client sends no cookie; noCSRF leaves the
// header off a non-GET call.
func (c *client) call(t *testing.T, method, path, body string, noCSRF bool, f *apiFixture) (int, string) {
	t.Helper()
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("")
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c != nil {
		req.Header.Set("Cookie", SessionCookie+"="+c.cookie)
		if method != "GET" && !noCSRF {
			req.Header.Set(CSRFHeader, c.csrf)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, readBody(t, resp)
}

func (c *client) get(t *testing.T, path string) (int, string) {
	return c.call(t, "GET", path, "", false, c.f)
}

func (c *client) post(t *testing.T, path, body string) (int, string) {
	return c.call(t, "POST", path, body, false, c.f)
}

func decode[T any](t *testing.T, body string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, body)
	}
	return v
}

const approvalID = "0123456789abcdef0123456789abcdef"

func (f *apiFixture) pending(t *testing.T, id string) store.Approval {
	t.Helper()
	imp, _ := json.Marshal(engine.Impact{
		Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1, Undo: "none",
		Effects:       []engine.Effect{{Kind: "deleted", Object: "PersistentVolumeClaim/demo/data"}},
		EndpointsLeft: map[string]int{"demo/web": 0}, PDBViolations: []string{"demo/web-pdb"},
	})
	act, _ := json.Marshal(normalize.Action{Verb: "delete", Resource: "persistentvolumeclaims", Namespace: "demo", Name: "data"})
	now := f.clock.Now()
	a := store.Approval{ID: id, Session: "0123456789abcdef", Human: "alice", Agent: "coding-agent",
		RequestDigest: "req-" + id, ImpactDigest: "imp", ActionJSON: act, ImpactJSON: imp,
		Rule: "data-destruction", Status: "pending", Created: now.Add(-90 * time.Second), Expires: now.Add(time.Hour)}
	if err := f.st.CreateApproval(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	return a
}

func keysOf(m map[string]any) []string {
	var k []string
	for key := range m {
		k = append(k, key)
	}
	sort.Strings(k)
	return k
}

func sorted(s ...string) []string { sort.Strings(s); return s }

func TestFeedPagesAndFilters(t *testing.T) {
	f := newAPIFixture(t)
	for i := range 7 {
		r := store.AuditRow{At: t0.Add(time.Duration(i) * time.Second), Kind: "decision", RequestID: fmt.Sprintf("r%d", i),
			Human: "alice", Agent: "coding-agent", Verb: "get", Resource: "pods", Class: "READ", Decision: "allow", Rule: "safe"}
		switch i {
		case 1, 4:
			r.Agent, r.Human = "other-agent", "bob"
		case 2:
			r.Class, r.Decision = "TERMINAL", "hold"
		case 5:
			r.Kind = "result"
		}
		if err := f.st.AppendAudit(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	c := f.signIn(t, "carol")
	page := func(q string) []map[string]any {
		t.Helper()
		code, body := c.get(t, "/api/feed"+q)
		if code != 200 {
			t.Fatalf("%s: %d %s", q, code, body)
		}
		return decode[[]map[string]any](t, body)
	}
	ids := func(rows []map[string]any) []string {
		var out []string
		for _, r := range rows {
			out = append(out, r["request_id"].(string))
		}
		return out
	}
	first := page("?limit=3")
	if got := ids(first); !slices.Equal(got, []string{"r6", "r5", "r4"}) {
		t.Fatalf("first page %v", got)
	}
	last := int64(first[2]["id"].(float64))
	if got := ids(page(fmt.Sprintf("?limit=3&before=%d", last))); !slices.Equal(got, []string{"r3", "r2", "r1"}) {
		t.Errorf("second page %v", got)
	}
	for q, want := range map[string][]string{
		"?agent=other-agent": {"r4", "r1"},
		"?agent=other":       nil, // exact match, not a prefix
		"?human=bob":         {"r4", "r1"},
		"?class=TERMINAL":    {"r2"},
		"?decision=hold":     {"r2"},
		"?kind=result":       {"r5"},
		"?agent=coding-agent&kind=decision&decision=allow": {"r6", "r3", "r0"},
	} {
		if got := ids(page(q)); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", q, got, want)
		}
	}
	// Default page is 50: all seven.
	all := page("")
	if len(all) != 7 {
		t.Errorf("default page: %d rows", len(all))
	}
	// The row is the export shape plus id; times are RFC3339.
	wantKeys := sorted("id", "at", "kind", "request_id", "session", "human", "agent", "source", "verb", "group",
		"resource", "subresource", "namespace", "name", "request_digest", "class", "measured", "rule", "decision",
		"approval_id", "status", "outcome", "latency_ms", "snapshot")
	if got := keysOf(all[0]); !slices.Equal(got, wantKeys) {
		t.Errorf("feed row keys %v\nwant %v", got, wantKeys)
	}
	if _, err := time.Parse(time.RFC3339, all[0]["at"].(string)); err != nil {
		t.Errorf("at is not RFC3339: %v", err)
	}
	if code, body := c.get(t, "/api/feed"+"?before=x"); code != 400 || body != `{"error":"bad query parameter"}` {
		t.Errorf("bad before: %d %s", code, body)
	}
	if code, _ := c.get(t, "/api/feed?limit=-1"); code != 400 {
		t.Errorf("negative limit: %d", code)
	}
	if code, body := c.get(t, "/api/feed?limit=9000000000"); code != 200 || len(decode[[]map[string]any](t, body)) != 7 {
		t.Errorf("huge limit is clamped, not refused: %d", code)
	}
	// An empty result is an empty array, not null: the UI maps over it.
	if code, body := c.get(t, "/api/feed?agent=nobody"); code != 200 || body != "[]" {
		t.Errorf("empty feed: %d %s", code, body)
	}
}

func TestApprovalDetailHasImpactButNoSecrets(t *testing.T) {
	f := newAPIFixture(t)
	f.pending(t, approvalID)
	// Approve through the service so the row carries a real nonce and
	// token, then read it through every API view that shows it.
	if _, err := f.svc.Approve(context.Background(), approvalID, "bob"); err != nil {
		t.Fatal(err)
	}
	row, err := f.st.ApprovalByID(context.Background(), approvalID)
	if err != nil || row.Nonce == "" || row.Token == "" {
		t.Fatalf("no secrets to look for: %v %+v", err, row)
	}
	c := f.signIn(t, "carol")
	code, body := c.get(t, "/api/approvals/"+approvalID)
	if code != 200 {
		t.Fatalf("detail: %d %s", code, body)
	}
	_, lbody := c.get(t, "/api/approvals")
	for name, b := range map[string]string{"detail": body, "list": lbody} {
		if strings.Contains(b, row.Nonce) || strings.Contains(b, row.Token) {
			t.Errorf("%s response carries the nonce or token:\n%s", name, b)
		}
		if strings.Contains(strings.ToLower(b), "nonce") || strings.Contains(strings.ToLower(b), "token") {
			t.Errorf("%s response has a nonce/token field:\n%s", name, b)
		}
	}
	d := decode[map[string]any](t, body)
	wantKeys := sorted("id", "status", "rule", "human", "agent", "verb", "resource", "namespace", "name", "summary",
		"class", "data_destroyed", "age_seconds", "created", "expires", "action", "impact", "decided_by", "decided")
	if got := keysOf(d); !slices.Equal(got, wantKeys) {
		t.Errorf("detail keys %v\nwant %v", got, wantKeys)
	}
	imp := d["impact"].(map[string]any)
	for _, k := range []string{"effects", "endpointsLeft", "pdbViolations", "dataDestroyed", "undo"} {
		if _, ok := imp[k]; !ok {
			t.Errorf("impact lacks %s: %v", k, imp)
		}
	}
	if d["action"].(map[string]any)["resource"] != "persistentvolumeclaims" {
		t.Errorf("action: %v", d["action"])
	}
	if d["status"] != "approved" || d["decided_by"] != "bob" || d["class"] != "TERMINAL" || d["data_destroyed"] != 1.0 ||
		d["age_seconds"] != 90.0 || d["verb"] != "delete" || d["name"] != "data" || d["namespace"] != "demo" {
		t.Errorf("detail fields: %v", d)
	}
	if _, err := time.Parse(time.RFC3339, d["decided"].(string)); err != nil {
		t.Errorf("decided: %v", err)
	}
	if code, body := c.get(t, "/api/approvals/ffffffffffffffffffffffffffffffff"); code != 404 || body != `{"error":"not found"}` {
		t.Errorf("unknown id: %d %s", code, body)
	}
}

func TestApprovalListShapeAndStatusFilter(t *testing.T) {
	f := newAPIFixture(t)
	f.pending(t, approvalID)
	f.pending(t, "ffffffffffffffffffffffffffffffff")
	if _, err := f.svc.Deny(context.Background(), "ffffffffffffffffffffffffffffffff", "bob"); err != nil {
		t.Fatal(err)
	}
	c := f.signIn(t, "carol")
	_, body := c.get(t, "/api/approvals?status=pending")
	l := decode[[]map[string]any](t, body)
	if len(l) != 1 || l[0]["id"] != approvalID {
		t.Fatalf("pending list: %s", body)
	}
	wantKeys := sorted("id", "status", "rule", "human", "agent", "verb", "resource", "namespace", "name", "summary",
		"class", "data_destroyed", "age_seconds", "created", "expires")
	if got := keysOf(l[0]); !slices.Equal(got, wantKeys) {
		t.Errorf("summary keys %v\nwant %v", got, wantKeys)
	}
	if l[0]["summary"] == "" || l[0]["summary"] == "unknown impact" || l[0]["data_destroyed"] != 1.0 || l[0]["class"] != "TERMINAL" {
		t.Errorf("summary: %v", l[0])
	}
	if _, body := c.get(t, "/api/approvals"); len(decode[[]map[string]any](t, body)) != 2 {
		t.Errorf("unfiltered list: %s", body)
	}
	// limit keeps the newest; over 500 is clamped, not refused.
	if _, body := c.get(t, "/api/approvals?limit=1"); len(decode[[]map[string]any](t, body)) != 1 {
		t.Errorf("limit=1: %s", body)
	}
	if code, body := c.get(t, "/api/approvals?limit=100000"); code != 200 || len(decode[[]map[string]any](t, body)) != 2 || f.cs.lastLimit.Load() != 500 {
		t.Errorf("limit=100000: %d, store asked for %d: %s", code, f.cs.lastLimit.Load(), body)
	}
	if c.get(t, "/api/approvals"); f.cs.lastLimit.Load() != 200 {
		t.Errorf("default limit: store asked for %d, want 200", f.cs.lastLimit.Load())
	}
	for _, q := range []string{"?limit=0", "?limit=-3", "?limit=x", "?limit=99999999999999999999"} {
		if code, body := c.get(t, "/api/approvals"+q); code != 400 || body != `{"error":"bad query parameter"}` {
			t.Errorf("%s: %d %s", q, code, body)
		}
	}
	if code, _ := c.get(t, "/api/approvals?status=bogus"); code != 400 {
		t.Errorf("unknown status: %d", code)
	}
}

func TestApproveRecordsTheSignedInApprover(t *testing.T) {
	f := newAPIFixture(t)
	f.pending(t, approvalID)
	c := f.signIn(t, "carol")
	// A body naming someone else is ignored: who decided is the session.
	code, body := c.post(t, "/api/approvals/"+approvalID+"/approve", `{"by":"mallory"}`)
	if code != 200 {
		t.Fatalf("approve: %d %s", code, body)
	}
	row, _ := f.st.ApprovalByID(context.Background(), approvalID)
	if row.DecidedBy != "carol" || row.Status != "approved" {
		t.Errorf("row decided_by=%q status=%q", row.DecidedBy, row.Status)
	}
	if strings.Contains(body, row.Nonce) || strings.Contains(body, row.Token) || strings.Contains(body, "mallory") {
		t.Errorf("approve response leaks a secret or the body's name:\n%s", body)
	}
	if d := decode[map[string]any](t, body); d["decided_by"] != "carol" || d["status"] != "approved" {
		t.Errorf("response: %v", d)
	}

	// Deny: same recording, same absence of secrets.
	f.pending(t, "ffffffffffffffffffffffffffffffff")
	code, body = c.post(t, "/api/approvals/ffffffffffffffffffffffffffffffff/deny", `{"by":"mallory"}`)
	row, _ = f.st.ApprovalByID(context.Background(), "ffffffffffffffffffffffffffffffff")
	if code != 200 || row.DecidedBy != "carol" || row.Status != "denied" {
		t.Errorf("deny: %d decided_by=%q status=%q", code, row.DecidedBy, row.Status)
	}
	if d := decode[map[string]any](t, body); d["decided_by"] != "carol" || d["status"] != "denied" {
		t.Errorf("deny response: %v", d)
	}
	if code, _ := c.post(t, "/api/approvals/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/approve", ""); code != 404 {
		t.Errorf("approve unknown: %d", code)
	}
	if code, _ := c.post(t, "/api/approvals/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/deny", ""); code != 404 {
		t.Errorf("deny unknown: %d", code)
	}
}

func TestApproveWithoutCSRFIsRefused(t *testing.T) {
	f := newAPIFixture(t)
	f.pending(t, approvalID)
	c := f.signIn(t, "carol")
	if code, _ := c.call(t, "POST", "/api/approvals/"+approvalID+"/approve", "", true, f); code != 403 {
		t.Errorf("no csrf header: %d", code)
	}
	wrong := *c
	wrong.csrf = "not-the-value"
	if code, _ := wrong.post(t, "/api/approvals/"+approvalID+"/approve", ""); code != 403 {
		t.Errorf("wrong csrf header: %d", code)
	}
	if code, _ := c.call(t, "POST", "/api/approvals/"+approvalID+"/deny", "", true, f); code != 403 {
		t.Errorf("deny without csrf: %d", code)
	}
	if row, _ := f.st.ApprovalByID(context.Background(), approvalID); row.Status != "pending" || row.DecidedBy != "" {
		t.Errorf("refused request changed the approval: %+v", row)
	}
}

func TestApproveTwiceIs409(t *testing.T) {
	f := newAPIFixture(t)
	f.pending(t, approvalID)
	c := f.signIn(t, "carol")
	if code, _ := c.post(t, "/api/approvals/"+approvalID+"/approve", ""); code != 200 {
		t.Fatalf("first approve: %d", code)
	}
	if code, body := c.post(t, "/api/approvals/"+approvalID+"/approve", ""); code != 409 || body != `{"error":"approval is not pending"}` {
		t.Errorf("second approve: %d %s", code, body)
	}
	if code, _ := c.post(t, "/api/approvals/"+approvalID+"/deny", ""); code != 409 {
		t.Errorf("deny after approve: %d", code)
	}
	// Pending but past its expiry is the wrong state too.
	f.pending(t, "ffffffffffffffffffffffffffffffff")
	f.clock.Add(2 * time.Hour)
	c2 := f.signIn(t, "dave")
	if code, _ := c2.post(t, "/api/approvals/ffffffffffffffffffffffffffffffff/approve", ""); code != 409 {
		t.Errorf("approve stale pending: %d", code)
	}
}

func TestSessionsListShowsState(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	for i, s := range []store.Session{
		{ID: "000000000000000a", Human: "alice", Agent: "coding-agent", Created: t0.Add(-time.Hour), Expires: t0.Add(time.Hour)},
		{ID: "000000000000000b", Human: "alice", Agent: "coding-agent", Created: t0.Add(-2 * time.Hour), Expires: t0.Add(-time.Minute)},
		{ID: "000000000000000c", Human: "bob", Agent: "coding-agent", Created: t0.Add(-3 * time.Hour), Expires: t0.Add(time.Hour)},
	} {
		if err := f.st.CreateSession(ctx, s, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.st.RevokeSession(ctx, "000000000000000c", t0); err != nil {
		t.Fatal(err)
	}
	c := f.signIn(t, "carol")
	_, body := c.get(t, "/api/sessions")
	l := decode[[]map[string]any](t, body)
	if len(l) != 3 {
		t.Fatalf("sessions: %s", body)
	}
	if got := keysOf(l[0]); !slices.Equal(got, sorted("id", "human", "agent", "created", "expires", "state")) {
		t.Errorf("session keys %v", got)
	}
	states := map[string]string{}
	for _, s := range l {
		states[s["id"].(string)] = s["state"].(string)
	}
	if states["000000000000000a"] != "active" || states["000000000000000b"] != "expired" || states["000000000000000c"] != "revoked" {
		t.Errorf("states %v", states)
	}
}

func TestRevokeSessionStopsTheAgent(t *testing.T) {
	f := newAPIFixture(t)
	sess, tok, err := session.New("alice", "coding-agent", time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.CreateSession(context.Background(), sess, session.Hash(tok)); err != nil {
		t.Fatal(err)
	}
	authn := &session.Authenticator{Store: f.st, Now: f.clock.Now}
	req := httptest.NewRequest("GET", "/api/v1/pods", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, err := authn.Authenticate(req); err != nil {
		t.Fatalf("session did not work before revoke: %v", err)
	}
	c := f.signIn(t, "carol")
	code, body := c.post(t, "/api/sessions/"+sess.ID+"/revoke", "")
	if code != 200 {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if d := decode[map[string]any](t, body); d["id"] != sess.ID || d["state"] != "revoked" {
		t.Errorf("revoke response: %s", body)
	}
	if _, err := authn.Authenticate(req); err != session.ErrUnauthenticated {
		t.Errorf("revoked session still authenticates: %v", err)
	}
	if code, _ := c.post(t, "/api/sessions/ffffffffffffffff/revoke", ""); code != 404 {
		t.Errorf("unknown session: %d", code)
	}
	if code, _ := c.call(t, "POST", "/api/sessions/"+sess.ID+"/revoke", "", true, f); code != 403 {
		t.Errorf("revoke without csrf: %d", code)
	}
}

// decisionRow is a scored decision the given policy decision made.
func decisionRow(at time.Time, id, rule, decision string, imp engine.Impact) store.AuditRow {
	a := normalize.Action{Verb: "delete", Resource: "pods", Subresource: "eviction", Namespace: "demo", Name: id}
	act, _ := json.Marshal(a)
	ij, _ := json.Marshal(imp)
	return store.AuditRow{At: at, Kind: "decision", RequestID: id, Verb: a.Verb, Resource: a.Resource, Subresource: a.Subresource,
		Namespace: a.Namespace, Name: a.Name, ActionJSON: act, ImpactJSON: ij, LabelsJSON: []byte(`{}`),
		Class: imp.Class, Measured: imp.Measured, Rule: rule, Decision: decision}
}

const allowEverything = `rules:
  - name: everything
    when: "true"
    then: allow
default: allow
unmeasured: hold
`

func TestPolicyReplayReportsChangesAndRejectsBadPolicy(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	terminal := engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1, Undo: "none"}
	reversible := engine.Impact{Class: engine.ClassReversible, Measured: true, Undo: "patch"}
	for _, r := range []store.AuditRow{
		decisionRow(t0.Add(-2*time.Minute), "r1", "data-destruction", "hold", terminal),
		decisionRow(t0.Add(-time.Minute), "r2", "safe", "allow", reversible),
		decisionRow(t0.Add(-3*time.Hour), "old", "data-destruction", "hold", terminal), // outside since_hours=1
		{At: t0.Add(-time.Minute), Kind: "decision", RequestID: "unscored", Decision: "deny"},
		{At: t0, Kind: "result", RequestID: "r2", Decision: "allow"},
	} {
		if err := f.st.AppendAudit(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	c := f.signIn(t, "carol")
	req, _ := json.Marshal(map[string]any{"policy": allowEverything, "since_hours": 1})
	code, body := c.post(t, "/api/policy/replay", string(req))
	if code != 200 {
		t.Fatalf("replay: %d %s", code, body)
	}
	res := decode[map[string]any](t, body)
	if got := keysOf(res); !slices.Equal(got, sorted("evaluated", "changed", "skipped", "truncated", "changes")) {
		t.Errorf("result keys %v", got)
	}
	if res["evaluated"] != 2.0 || res["changed"] != 1.0 || res["skipped"] != 1.0 || res["truncated"] != false {
		t.Errorf("counts: %s", body)
	}
	ch := res["changes"].([]any)
	if len(ch) != 1 {
		t.Fatalf("changes: %s", body)
	}
	c0 := ch[0].(map[string]any)
	if got := keysOf(c0); !slices.Equal(got, sorted("at", "request_id", "verb", "resource", "namespace", "name",
		"rule_before", "rule_after", "decision_before", "decision_after")) {
		t.Errorf("change keys %v", got)
	}
	if c0["request_id"] != "r1" || c0["resource"] != "pods/eviction" || c0["rule_before"] != "data-destruction" ||
		c0["rule_after"] != "everything" || c0["decision_before"] != "hold" || c0["decision_after"] != "allow" {
		t.Errorf("change: %v", c0)
	}

	// Nothing changes: changes is [], not null.
	same := "rules:\n  - name: safe\n    when: impact.class == \"REVERSIBLE\"\n    then: allow\ndefault: hold\nunmeasured: hold\n"
	req, _ = json.Marshal(map[string]any{"policy": same, "since_hours": 1})
	_, body = c.post(t, "/api/policy/replay", string(req))
	if !strings.Contains(body, `"changed":0`) || !strings.Contains(body, `"changes":[]`) {
		t.Errorf("no-change replay: %s", body)
	}

	// A policy that does not parse: 400 with the parser's own message.
	req, _ = json.Marshal(map[string]any{"policy": "rules: [nope", "since_hours": 1})
	code, body = c.post(t, "/api/policy/replay", string(req))
	if e := decode[map[string]string](t, body)["error"]; code != 400 || e == "" || e == "internal error" {
		t.Errorf("unparseable policy: %d %s", code, body)
	}
	req, _ = json.Marshal(map[string]any{"policy": strings.Replace(allowEverything, "unmeasured: hold", "unmeasured: allow", 1), "since_hours": 1})
	if code, body := c.post(t, "/api/policy/replay", string(req)); code != 400 || !strings.Contains(body, "unmeasured") {
		t.Errorf("unmeasured allow: %d %s", code, body)
	}

	for name, b := range map[string]string{
		"since 0":        `{"policy":"default: hold\nunmeasured: hold\n","since_hours":0}`,
		"since missing":  `{"policy":"default: hold\nunmeasured: hold\n"}`,
		"since 721":      `{"policy":"default: hold\nunmeasured: hold\n","since_hours":721}`,
		"unknown field":  `{"policy":"default: hold\n","since_hours":1,"extra":1}`,
		"trailing data":  `{"policy":"default: hold\n","since_hours":1} {}`,
		"not json":       `policy=x`,
		"oversize body":  `{"policy":"` + strings.Repeat("a", 64<<10+1) + `","since_hours":1}`,
		"since a string": `{"policy":"default: hold\n","since_hours":"1"}`,
	} {
		code, body := c.post(t, "/api/policy/replay", b)
		if code != 400 {
			t.Errorf("%s: %d %s", name, code, body)
		}
		if strings.HasPrefix(name, "since ") && name != "since a string" && body != `{"error":"since_hours must be between 1 and 720"}` {
			t.Errorf("%s: body %s", name, body)
		}
	}
	if code, _ := c.call(t, "POST", "/api/policy/replay", string(req), true, f); code != 403 {
		t.Errorf("replay without csrf: %d", code)
	}
}

func TestPolicyReplayCapsChangesAt500(t *testing.T) {
	f := newAPIFixture(t)
	terminal := engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1, Undo: "none"}
	for i := range 501 {
		if err := f.st.AppendAudit(context.Background(), decisionRow(t0.Add(-time.Minute), fmt.Sprintf("r%d", i), "data-destruction", "hold", terminal)); err != nil {
			t.Fatal(err)
		}
	}
	c := f.signIn(t, "carol")
	req, _ := json.Marshal(map[string]any{"policy": allowEverything, "since_hours": 1})
	code, body := c.post(t, "/api/policy/replay", string(req))
	res := decode[struct {
		Evaluated, Changed int
		Changes            []any
	}](t, body)
	if code != 200 || res.Evaluated != 501 || res.Changed != 501 || len(res.Changes) != 500 {
		t.Errorf("code %d evaluated %d changed %d listed %d", code, res.Evaluated, res.Changed, len(res.Changes))
	}
}

func TestPolicyAndMe(t *testing.T) {
	f := newAPIFixture(t)
	c := f.signIn(t, "carol")
	_, body := c.get(t, "/api/policy")
	if p := decode[map[string]string](t, body); p["source"] != "/etc/blastgate/policy.yaml" || p["text"] != testPolicyText || len(p) != 2 {
		t.Errorf("policy: %s", body)
	}
	_, body = c.get(t, "/api/me")
	if m := decode[map[string]string](t, body); m["name"] != "carol" || m["csrf"] != c.csrf || len(m) != 2 {
		t.Errorf("me: %s", body)
	}
}

func TestBypassListsNewestFirst(t *testing.T) {
	f := newAPIFixture(t)
	for i, at := range []time.Time{t0.Add(-3 * time.Minute), t0.Add(-time.Minute), t0.Add(-2 * time.Minute), t0.Add(-48 * time.Hour)} {
		b := store.BypassRow{At: at, User: fmt.Sprintf("u%d", i), Groups: []string{"system:authenticated"}, Verb: "delete",
			Resource: "pods", Namespace: "demo", Name: fmt.Sprintf("p%d", i), UID: "uid", DryRun: i == 1}
		if i == 2 {
			b.Groups = nil
		}
		if err := f.st.AppendBypass(context.Background(), b); err != nil {
			t.Fatal(err)
		}
	}
	c := f.signIn(t, "carol")
	users := func(q string) []string {
		t.Helper()
		code, body := c.get(t, "/api/bypass"+q)
		if code != 200 {
			t.Fatalf("%s: %d %s", q, code, body)
		}
		var out []string
		for _, r := range decode[[]map[string]any](t, body) {
			out = append(out, r["user"].(string))
		}
		return out
	}
	if got := users(""); !slices.Equal(got, []string{"u1", "u2", "u0"}) {
		t.Errorf("default (24h) %v", got)
	}
	if got := users("?since_hours=72"); !slices.Equal(got, []string{"u1", "u2", "u0", "u3"}) {
		t.Errorf("72h %v", got)
	}
	if got := users("?limit=2"); !slices.Equal(got, []string{"u1", "u2"}) {
		t.Errorf("limit 2 %v", got)
	}
	_, body := c.get(t, "/api/bypass?limit=2")
	l := decode[[]map[string]any](t, body)
	if got := keysOf(l[0]); !slices.Equal(got, sorted("at", "user", "groups", "verb", "group", "resource", "subresource",
		"namespace", "name", "uid", "dry_run")) {
		t.Errorf("bypass keys %v", got)
	}
	if l[0]["dry_run"] != true || l[1]["groups"] == nil {
		t.Errorf("fields: %s", body)
	}
	// BypassSince has no clamp of its own: the API's is the only bound.
	if code, _ := c.get(t, "/api/bypass?limit=1000000"); code != 200 || f.cs.lastLimit.Load() != 500 {
		t.Errorf("huge bypass limit: %d, store asked for %d", code, f.cs.lastLimit.Load())
	}
	for _, q := range []string{"?since_hours=0", "?since_hours=721", "?limit=0", "?limit=x"} {
		if code, _ := c.get(t, "/api/bypass"+q); code != 400 {
			t.Errorf("%s: %d", q, code)
		}
	}
}

func TestIDsAreValidatedBeforeLookup(t *testing.T) {
	f := newAPIFixture(t)
	c := f.signIn(t, "carol")
	bad := []string{
		"..%2Fx", "%2E%2E%2Fx",
		strings.ToUpper(approvalID), approvalID[:31], approvalID + "0", approvalID[:31] + "g",
		"0123456789ABCDEF", "0123456789abcde", "0123456789abcdef0", "%00123456789abcde",
	}
	before := f.cs.n.Load()
	for _, id := range bad {
		for _, rt := range []struct{ method, path string }{
			{"GET", "/api/approvals/" + id},
			{"POST", "/api/approvals/" + id + "/approve"},
			{"POST", "/api/approvals/" + id + "/deny"},
			{"POST", "/api/sessions/" + id + "/revoke"},
		} {
			code, body := c.call(t, rt.method, rt.path, "", false, f)
			if code != 404 || body != `{"error":"not found"}` {
				t.Errorf("%s %s: %d %s", rt.method, rt.path, code, body)
			}
		}
	}
	if n := f.cs.n.Load() - before; n != 0 {
		t.Errorf("%d store calls for ids that should never reach it", n)
	}
	// And the counter does count: a well-formed id is looked up.
	c.get(t, "/api/approvals/"+approvalID)
	c.post(t, "/api/sessions/0123456789abcdef/revoke", "")
	if f.cs.n.Load() == before {
		t.Error("the counting store saw no call for a valid id; the check above proved nothing")
	}
}

func TestEveryAPIRouteNeedsASession(t *testing.T) {
	f := newAPIFixture(t)
	f.pending(t, approvalID)
	routes := []struct{ method, path string }{
		{"POST", "/api/logout"},
		{"GET", "/api/me"},
		{"GET", "/api/feed"},
		{"GET", "/api/approvals"},
		{"GET", "/api/approvals/" + approvalID},
		{"POST", "/api/approvals/" + approvalID + "/approve"},
		{"POST", "/api/approvals/" + approvalID + "/deny"},
		{"GET", "/api/sessions"},
		{"POST", "/api/sessions/0123456789abcdef/revoke"},
		{"GET", "/api/policy"},
		{"POST", "/api/policy/replay"},
		{"GET", "/api/bypass"},
		{"GET", "/api/stream"},
		{"GET", "/api/no-such-route"},
	}
	stale := &client{f: f, cookie: "not-a-session", csrf: "x"}
	for _, rt := range routes {
		for name, c := range map[string]*client{"no cookie": nil, "unknown cookie": stale} {
			code, body := c.call(t, rt.method, rt.path, `{"policy":"default: allow\n","since_hours":1}`, false, f)
			if code != 401 || body != `{"error":"unauthenticated"}` {
				t.Errorf("%s %s (%s): %d %s", rt.method, rt.path, name, code, body)
			}
		}
	}
	if row, _ := f.st.ApprovalByID(context.Background(), approvalID); row.Status != "pending" {
		t.Errorf("an unauthenticated call decided the approval: %s", row.Status)
	}
	// A logged-out session is refused everywhere too.
	c := f.signIn(t, "carol")
	if code, _ := c.post(t, "/api/logout", ""); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	for _, rt := range routes {
		if code, _ := c.call(t, rt.method, rt.path, "", false, f); code != 401 {
			t.Errorf("%s %s after logout: %d", rt.method, rt.path, code)
		}
	}
}

func TestAPIResponsesAreNotCached(t *testing.T) {
	f := newAPIFixture(t)
	c := f.signIn(t, "carol")
	req, _ := http.NewRequest("GET", f.srv.URL+"/api/feed", nil)
	req.Header.Set("Cookie", SessionCookie+"="+c.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("headers: %v", resp.Header)
	}
}

func TestPolicyReplayStopsAtTheRowCap(t *testing.T) {
	f := newAPIFixture(t)
	old := replayRowCap
	replayRowCap = 3
	t.Cleanup(func() { replayRowCap = old })
	terminal := engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1, Undo: "none"}
	// Each row is a minute newer than the one before and carries its own
	// request id, so which rows were evaluated is visible in the changes.
	next := 0
	seed := func(n int) {
		for range n {
			r := decisionRow(t0.Add(-time.Duration(10-next)*time.Minute), fmt.Sprintf("r%d", next), "data-destruction", "hold", terminal)
			if err := f.st.AppendAudit(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			next++
		}
	}
	c := f.signIn(t, "carol")
	replayOnce := func() map[string]any {
		t.Helper()
		req, _ := json.Marshal(map[string]any{"policy": allowEverything, "since_hours": 1})
		code, body := c.post(t, "/api/policy/replay", string(req))
		if code != 200 {
			t.Fatalf("replay: %d %s", code, body)
		}
		return decode[map[string]any](t, body)
	}
	// Exactly the cap: all evaluated, nothing left over, not truncated.
	seed(3)
	if res := replayOnce(); res["evaluated"] != 3.0 || res["truncated"] != false {
		t.Errorf("at the cap: %v", res)
	}
	seed(2)
	res := replayOnce()
	if res["evaluated"] != 3.0 || res["changed"] != 3.0 || res["truncated"] != true {
		t.Errorf("past the cap: %v", res)
	}
	// The newest rows are the ones evaluated (P2-R21), in the order they
	// happened: an approver checking a policy change cares about what
	// the gateway is seeing now, not what it saw a month ago.
	var ids []string
	for _, c := range res["changes"].([]any) {
		ids = append(ids, c.(map[string]any)["request_id"].(string))
	}
	if strings.Join(ids, ",") != "r2,r3,r4" {
		t.Errorf("evaluated %v, want the newest three r2,r3,r4 oldest first", ids)
	}
}

func TestOnlyOneReplayAtATime(t *testing.T) {
	f := newAPIFixture(t)
	c := f.signIn(t, "carol")
	entered, release := make(chan struct{}), make(chan struct{})
	// Only the first call blocks. A later one that got past a broken
	// slot must fall through, not queue behind the first, or the test
	// would deadlock instead of failing.
	var first atomic.Bool
	f.cs.setHooks(func() {
		if first.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
	}, nil)
	req, _ := json.Marshal(map[string]any{"policy": allowEverything, "since_hours": 1})
	firstCode := make(chan int, 1)
	// Sent by hand: t.Fatal (inside c.post) must not run off the test's
	// own goroutine.
	go func() {
		hr, _ := http.NewRequest("POST", f.srv.URL+"/api/policy/replay", strings.NewReader(string(req)))
		hr.Header.Set("Content-Type", "application/json")
		hr.Header.Set("Cookie", SessionCookie+"="+c.cookie)
		hr.Header.Set(CSRFHeader, c.csrf)
		resp, err := http.DefaultClient.Do(hr)
		if err != nil {
			firstCode <- -1
			return
		}
		resp.Body.Close()
		firstCode <- resp.StatusCode
	}()
	<-entered // the first replay holds the slot and is blocked in the store
	// The second must be refused at once, not queued behind the first: a
	// client timeout turns a queued request into a failure, not a hang.
	hr, _ := http.NewRequest("POST", f.srv.URL+"/api/policy/replay", strings.NewReader(string(req)))
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Cookie", SessionCookie+"="+c.cookie)
	hr.Header.Set(CSRFHeader, c.csrf)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(hr)
	if err != nil {
		close(release)
		t.Fatalf("second replay was not refused at once: %v", err)
	}
	body := readBody(t, resp)
	resp.Body.Close()
	if resp.StatusCode != 429 || body != `{"error":"a replay is already running; try again when it finishes"}` {
		t.Errorf("second replay: %d %s", resp.StatusCode, body)
	}
	close(release)
	if code := <-firstCode; code != 200 {
		t.Errorf("first replay: %d", code)
	}
	// The slot is released: a later replay runs.
	if code, body := c.post(t, "/api/policy/replay", string(req)); code != 200 {
		t.Errorf("replay after the first finished: %d %s", code, body)
	}
}

// Another approver's decision landing between Approve's pending check and
// its compare-and-swap is ErrConflict from the store: the same 409 as
// finding it already decided, and the winner's decision stands.
func TestConcurrentDecisionIs409(t *testing.T) {
	f := newAPIFixture(t)
	f.pending(t, approvalID)
	c := f.signIn(t, "carol")
	f.cs.setHooks(nil, func(ctx context.Context, id string) {
		now := f.clock.Now()
		if err := f.st.DecideApproval(ctx, id, "denied", "dave", "", "", now, now.Add(time.Hour)); err != nil {
			t.Errorf("dave's deny: %v", err)
		}
	})
	code, body := c.post(t, "/api/approvals/"+approvalID+"/approve", "")
	if code != 409 || body != `{"error":"approval is not pending"}` {
		t.Errorf("losing approve: %d %s", code, body)
	}
	row, _ := f.st.ApprovalByID(context.Background(), approvalID)
	if row.Status != "denied" || row.DecidedBy != "dave" || row.Token != "" {
		t.Errorf("row after the race: status=%q decided_by=%q token set=%v", row.Status, row.DecidedBy, row.Token != "")
	}
}
