package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SaiPisey2/blastgate/internal/store"
)

var t0 = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type fixture struct {
	st    *store.Store
	dir   string
	auth  *Auth
	clock *clock
	logs  *syncBuffer
	srv   *httptest.Server
}

// syncBuffer lets the handler goroutines of httptest.Server write log
// lines while the test reads them without a data race.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "blastgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &fixture{st: st, dir: dir, clock: &clock{t: t0}, logs: &syncBuffer{}}
	f.auth = NewAuth(st, slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	f.auth.Now = f.clock.Now
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", f.auth.Login)
	mux.HandleFunc("POST /api/logout", f.auth.Logout)
	ok := func(w http.ResponseWriter, r *http.Request, u store.UISession) {
		io.WriteString(w, "hello "+u.ApproverName)
	}
	mux.Handle("GET /api/me", f.auth.Require(ok))
	mux.Handle("POST /api/thing", f.auth.Require(ok))
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) approver(t *testing.T, id, name string) string {
	t.Helper()
	tok, h := NewLoginToken()
	if err := f.st.CreateApprover(context.Background(), store.Approver{ID: id, Name: name, Created: f.clock.Now()}, h); err != nil {
		t.Fatal(err)
	}
	return tok
}

func (f *fixture) do(t *testing.T, method, path, body string, hdr map[string]string) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func readBody(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type loginResult struct {
	cookie *http.Cookie
	raw    string // the Set-Cookie header exactly as sent
	name   string
	csrf   string
}

func jsonHdr() map[string]string { return map[string]string{"Content-Type": "application/json"} }

func (f *fixture) login(t *testing.T, tok string) loginResult {
	t.Helper()
	return f.loginWith(t, tok, jsonHdr())
}

func (f *fixture) loginWith(t *testing.T, tok string, hdr map[string]string) loginResult {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"token": tok})
	resp := f.do(t, "POST", "/api/login", string(b), hdr)
	if resp.StatusCode != 200 {
		t.Fatalf("login status %d: %s", resp.StatusCode, readBody(t, resp))
	}
	var out struct{ Name, CSRF string }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	cs := resp.Cookies()
	if len(cs) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cs))
	}
	return loginResult{cookie: cs[0], raw: resp.Header.Get("Set-Cookie"), name: out.Name, csrf: out.CSRF}
}

func cookieHdr(c *http.Cookie) map[string]string {
	return map[string]string{"Cookie": SessionCookie + "=" + c.Value}
}

func TestLoginSetsAStrictCookieAndReturnsCSRF(t *testing.T) {
	f := newFixture(t)
	tok := f.approver(t, "a1", "alice")
	lr := f.login(t, tok)
	c := lr.cookie
	if c.Name != SessionCookie || c.Value == "" {
		t.Fatalf("cookie %q=%q", c.Name, c.Value)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Errorf("cookie flags: HttpOnly=%v Secure=%v SameSite=%v Path=%q", c.HttpOnly, c.Secure, c.SameSite, c.Path)
	}
	// The parsed cookie hides spelling; check the wire form too.
	for _, want := range []string{"HttpOnly", "Secure", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(lr.raw, want) {
			t.Errorf("Set-Cookie %q lacks %q", lr.raw, want)
		}
	}
	if lr.name != "alice" || lr.csrf == "" {
		t.Errorf("body name=%q csrf=%q", lr.name, lr.csrf)
	}
	// The DB (and its WAL) must hold only the hash of the cookie value.
	ents, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(f.dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		seen += len(b)
		if bytes.Contains(b, []byte(c.Value)) {
			t.Errorf("raw cookie value found in %s", e.Name())
		}
		if bytes.Contains(b, []byte(tok)) {
			t.Errorf("raw login token found in %s", e.Name())
		}
	}
	if seen == 0 {
		t.Fatal("no database bytes read; the check proved nothing")
	}
	// And the session it names works.
	if r := f.do(t, "GET", "/api/me", "", cookieHdr(c)); r.StatusCode != 200 || readBody(t, r) != "hello alice" {
		t.Errorf("session did not authenticate: %d", r.StatusCode)
	}
}

func TestLoginRefusals(t *testing.T) {
	f := newFixture(t)
	tok := f.approver(t, "a1", "alice")
	revoked := f.approver(t, "a2", "bob")
	if err := f.st.RevokeApprover(context.Background(), "a2", t0); err != nil {
		t.Fatal(err)
	}
	unknown, _ := NewLoginToken()
	good := `{"token":"` + tok + `"}`
	const js = "application/json"
	// Most cases carry the live token, so a refusal proves the check in
	// question and not merely an unknown token.
	cases := map[string]struct{ ct, body string }{
		"missing body":     {js, ""},
		"not json":         {js, "token=" + tok},
		"wrong prefix":     {js, `{"token":"` + strings.TrimPrefix(tok, LoginTokenPrefix) + `"}`},
		"unknown token":    {js, `{"token":"` + unknown + `"}`},
		"revoked approver": {js, `{"token":"` + revoked + `"}`},
		"oversized body":   {js, `{"token":"` + tok + `","pad":"` + strings.Repeat("x", 5000) + `"}`},
		// A cross-site <form enctype="text/plain"> can post a JSON-looking
		// body; only a script (which the same-origin policy stops at a
		// preflight) can send application/json.
		"text/plain":         {"text/plain", good},
		"form encoded":       {"application/x-www-form-urlencoded", good},
		"no content type":    {"", good},
		"json lookalike":     {"application/jsonx", good},
		"unknown field":      {js, `{"token":"` + tok + `","x":1}`},
		"unknown string key": {js, `{"note":"hi","token":"` + tok + `"}`},
		"trailing object":    {js, good + good},
		"trailing garbage":   {js, good + " x"},
		"duplicate token":    {js, `{"token":"bga_decoy","token":"` + tok + `"}`},
		"duplicate, same":    {js, `{"token":"` + tok + `","token":"` + tok + `"}`},
		"case-folded key":    {js, `{"TOKEN":"` + tok + `"}`},
		"token not string":   {js, `{"token":1}`},
		"array":              {js, `["` + tok + `"]`},
		"empty object":       {js, `{}`},
		"null":               {js, `null`},
	}
	var first string
	i := 0
	for name, c := range cases {
		// A fresh limiter per case: there are more cases than the limit
		// allows from one address, and every request here comes from the
		// same loopback host.
		f.auth.limiter = newLimiter()
		var hdr map[string]string
		if c.ct != "" {
			hdr = map[string]string{"Content-Type": c.ct}
		}
		resp := f.do(t, "POST", "/api/login", c.body, hdr)
		got := readBody(t, resp)
		if resp.StatusCode != 401 {
			t.Errorf("%s: status %d", name, resp.StatusCode)
		}
		if len(resp.Cookies()) != 0 {
			t.Errorf("%s: set a cookie", name)
		}
		if i == 0 {
			first = got
		} else if got != first {
			t.Errorf("%s: body %q differs from %q", name, got, first)
		}
		i++
	}
}

func TestLoginAcceptsJSONWithParametersAndATrailingNewline(t *testing.T) {
	f := newFixture(t)
	tok := f.approver(t, "a1", "alice")
	if lr := f.loginWith(t, tok, map[string]string{"Content-Type": "application/json; charset=utf-8"}); lr.name != "alice" {
		t.Errorf("name %q", lr.name)
	}
	r := f.do(t, "POST", "/api/login", `{"token":"`+tok+`"}`+"\n", jsonHdr())
	if r.StatusCode != 200 {
		t.Errorf("trailing newline: %d", r.StatusCode)
	}
}

// Logging in again from a browser that still holds a session ends that
// session: two live cookies for one browser means the older one, if it
// was copied somewhere, outlives what the approver thinks is their only
// session.
func TestLoginRevokesThePreviousSession(t *testing.T) {
	f := newFixture(t)
	tok := f.approver(t, "a1", "alice")
	old := f.login(t, tok)
	hdr := jsonHdr()
	hdr["Cookie"] = SessionCookie + "=" + old.cookie.Value
	fresh := f.loginWith(t, tok, hdr)
	if fresh.cookie.Value == old.cookie.Value {
		t.Fatal("login reused the old session id")
	}
	assertCleared(t, "old session", f.do(t, "GET", "/api/me", "", cookieHdr(old.cookie)))
	if r := f.do(t, "GET", "/api/me", "", cookieHdr(fresh.cookie)); r.StatusCode != 200 {
		t.Errorf("new session: %d", r.StatusCode)
	}
	// A cookie naming nothing does not stop the login.
	hdr["Cookie"] = SessionCookie + "=bogus"
	f.loginWith(t, tok, hdr)
}

func TestLoginIsRateLimitedPerIP(t *testing.T) {
	f := newFixture(t)
	bad := `{"token":"bga_nope"}`
	post := func(ip string) int {
		req := httptest.NewRequest("POST", "/api/login", strings.NewReader(bad))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = ip + ":40000"
		w := httptest.NewRecorder()
		f.auth.Login(w, req)
		return w.Code
	}
	for i := 1; i <= 5; i++ {
		if c := post("10.0.0.1"); c != 401 {
			t.Fatalf("attempt %d: %d, want 401", i, c)
		}
	}
	if c := post("10.0.0.1"); c != 429 {
		t.Errorf("6th attempt: %d, want 429", c)
	}
	if c := post("10.0.0.2"); c != 401 {
		t.Errorf("other IP: %d, want 401", c)
	}
	// A different source port is the same host.
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(bad))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.1:50000"
	w := httptest.NewRecorder()
	f.auth.Login(w, req)
	if w.Code != 429 {
		t.Errorf("same host, new port: %d, want 429", w.Code)
	}
	// Even a valid token is refused while limited: 429 comes before any lookup.
	tok := f.approver(t, "a1", "alice")
	req = httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"token":"`+tok+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.1:1"
	w = httptest.NewRecorder()
	f.auth.Login(w, req)
	if w.Code != 429 {
		t.Errorf("valid token while limited: %d, want 429", w.Code)
	}
	f.clock.Add(time.Minute)
	if c := post("10.0.0.1"); c != 401 {
		t.Errorf("after the window: %d, want 401", c)
	}
	if n := f.auth.limiter.size(); n != 1 {
		t.Errorf("limiter holds %d hosts after the window, want 1 (pruned)", n)
	}
}

func TestRequireRefusesWithoutASession(t *testing.T) {
	f := newFixture(t)
	for name, hdr := range map[string]map[string]string{
		"no cookie":      nil,
		"unknown cookie": {"Cookie": SessionCookie + "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		"empty cookie":   {"Cookie": SessionCookie + "="},
	} {
		if r := f.do(t, "GET", "/api/me", "", hdr); r.StatusCode != 401 {
			t.Errorf("%s: %d, want 401", name, r.StatusCode)
		}
	}
}

func TestStateChangingCallsNeedTheCSRFHeader(t *testing.T) {
	f := newFixture(t)
	lr := f.login(t, f.approver(t, "a1", "alice"))
	h := func(csrf string) map[string]string {
		m := cookieHdr(lr.cookie)
		if csrf != "" {
			m[CSRFHeader] = csrf
		}
		return m
	}
	if r := f.do(t, "POST", "/api/thing", "", h("")); r.StatusCode != 403 {
		t.Errorf("no header: %d, want 403", r.StatusCode)
	}
	if r := f.do(t, "POST", "/api/thing", "", h(lr.csrf+"x")); r.StatusCode != 403 {
		t.Errorf("wrong header: %d, want 403", r.StatusCode)
	}
	if r := f.do(t, "POST", "/api/thing", "", h(lr.csrf[:len(lr.csrf)-1])); r.StatusCode != 403 {
		t.Errorf("prefix of the header: %d, want 403", r.StatusCode)
	}
	// Another session's CSRF value is not this session's.
	other := f.login(t, f.approver(t, "a2", "bob"))
	if r := f.do(t, "POST", "/api/thing", "", h(other.csrf)); r.StatusCode != 403 {
		t.Errorf("other session's csrf: %d, want 403", r.StatusCode)
	}
	if r := f.do(t, "POST", "/api/thing", "", h(lr.csrf)); r.StatusCode != 200 {
		t.Errorf("right header: %d, want 200", r.StatusCode)
	}
	if r := f.do(t, "GET", "/api/me", "", h("")); r.StatusCode != 200 {
		t.Errorf("GET without header: %d, want 200", r.StatusCode)
	}
	// No session beats no CSRF: 401, not 403, so the UI knows to log in.
	if r := f.do(t, "POST", "/api/thing", "", nil); r.StatusCode != 401 {
		t.Errorf("POST without a session: %d, want 401", r.StatusCode)
	}
}

func assertCleared(t *testing.T, name string, r *http.Response) {
	t.Helper()
	if r.StatusCode != 401 {
		t.Errorf("%s: %d, want 401", name, r.StatusCode)
	}
	for _, c := range r.Cookies() {
		if c.Name == SessionCookie && c.MaxAge < 0 && c.Value == "" {
			return
		}
	}
	t.Errorf("%s: cookie not cleared: %q", name, r.Header.Values("Set-Cookie"))
}

func TestLogoutAndRevokeEndTheSession(t *testing.T) {
	f := newFixture(t)
	tok := f.approver(t, "a1", "alice")

	lr := f.login(t, tok)
	r := f.do(t, "POST", "/api/logout", "", map[string]string{"Cookie": SessionCookie + "=" + lr.cookie.Value, CSRFHeader: lr.csrf})
	if r.StatusCode != 204 {
		t.Errorf("logout: %d", r.StatusCode)
	}
	assertCleared(t, "after logout", f.do(t, "GET", "/api/me", "", cookieHdr(lr.cookie)))

	lr = f.login(t, tok)
	if err := f.st.RevokeApprover(context.Background(), "a1", f.clock.Now()); err != nil {
		t.Fatal(err)
	}
	assertCleared(t, "after approver revoke", f.do(t, "GET", "/api/me", "", cookieHdr(lr.cookie)))

	tok2 := f.approver(t, "a2", "carol")
	lr = f.login(t, tok2)
	f.clock.Add(SessionTTL - time.Second)
	if r := f.do(t, "GET", "/api/me", "", cookieHdr(lr.cookie)); r.StatusCode != 200 {
		t.Errorf("just before expiry: %d", r.StatusCode)
	}
	f.clock.Add(time.Second)
	assertCleared(t, "at expiry", f.do(t, "GET", "/api/me", "", cookieHdr(lr.cookie)))
}

// A session whose own row is live but whose approver is revoked: the
// race where Login read the approver as live, RevokeApprover committed
// (revoking every session that existed), and then Login inserted the new
// session. RevokeApprover's sweep never saw that row, so Require has to
// check the approver itself.
func TestRequireRefusesASessionOfARevokedApprover(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, h := NewLoginToken()
	if err := f.st.CreateApprover(ctx, store.Approver{ID: "a1", Name: "alice", Created: t0, Revoked: t0}, h); err != nil {
		t.Fatal(err)
	}
	id := "c2Vzc2lvbi1pZC1mb3ItdGhlLXJhY2UtdGVzdC0xMjM0NQ"
	u := store.UISession{ApproverID: "a1", CSRF: "csrf", Created: t0, Expires: t0.Add(SessionTTL)}
	if err := f.st.CreateUISession(ctx, u, hashOf(id)); err != nil {
		t.Fatal(err)
	}
	assertCleared(t, "revoked approver, live session", f.do(t, "GET", "/api/me", "", map[string]string{"Cookie": SessionCookie + "=" + id}))
}

func TestLogsNeverContainTheToken(t *testing.T) {
	f := newFixture(t)
	tok := f.approver(t, "a1", "alice")
	revoked := f.approver(t, "a2", "bob")
	if err := f.st.RevokeApprover(context.Background(), "a2", t0); err != nil {
		t.Fatal(err)
	}
	unknown, _ := NewLoginToken()
	lr := f.login(t, tok)
	for _, bad := range []string{unknown, revoked, strings.TrimPrefix(unknown, LoginTokenPrefix)} {
		f.do(t, "POST", "/api/login", `{"token":"`+bad+`"}`, jsonHdr())
	}
	f.do(t, "GET", "/api/me", "", cookieHdr(lr.cookie))
	f.do(t, "POST", "/api/thing", "", map[string]string{"Cookie": SessionCookie + "=" + lr.cookie.Value, CSRFHeader: "wrong"})
	f.do(t, "POST", "/api/logout", "", cookieHdr(lr.cookie))
	f.do(t, "GET", "/api/me", "", cookieHdr(lr.cookie))
	logs := f.logs.String()
	if !strings.Contains(logs, "login refused") {
		t.Fatalf("failed logins were not logged at all:\n%s", logs)
	}
	secrets := []string{tok, revoked, unknown, lr.cookie.Value, lr.csrf,
		strings.TrimPrefix(tok, LoginTokenPrefix), strings.TrimPrefix(unknown, LoginTokenPrefix)}
	for _, s := range secrets {
		if strings.Contains(logs, s) {
			t.Errorf("log contains a secret %q:\n%s", s, logs)
		}
	}
}
