package admin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

const testIndex = `<!doctype html><script type="module" src="/assets/app-1.js"></script>`

var testUI = fstest.MapFS{
	"index.html":      {Data: []byte(testIndex)},
	"favicon.svg":     {Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)},
	"assets/app-1.js": {Data: []byte(`console.log("ui")`)},
}

// newServerFixture is the API fixture served through NewServer, the
// handler serve mounts, instead of the bare mux: headers, static files
// and the stream are exercised as the admin listener runs them.
func newServerFixture(t *testing.T) *apiFixture {
	t.Helper()
	f := newAPIFixture(t)
	srv := httptest.NewServer(NewServer(f.auth, Deps{Store: f.st, Approvals: f.svc, PolicySource: "embedded default",
		PolicyText: []byte(testPolicyText), Log: slog.New(slog.DiscardHandler)}, testUI))
	t.Cleanup(srv.Close)
	f.srv = srv
	return f
}

func send(t *testing.T, f *apiFixture, method, path string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	// No redirects followed: the header check must see the answer to
	// exactly this request.
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

var securityHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
	"X-Content-Type-Options":  "nosniff",
	"Referrer-Policy":         "no-referrer",
	"X-Frame-Options":         "DENY",
}

func TestSecurityHeaders(t *testing.T) {
	f := newServerFixture(t)
	c := f.signIn(t, "bob")
	cookie := map[string]string{"Cookie": SessionCookie + "=" + c.cookie}
	for _, tc := range []struct {
		method, path string
		hdr          map[string]string
		code         int
	}{
		{"GET", "/", nil, 200},
		{"GET", "/index.html", nil, 200},
		{"GET", "/assets/app-1.js", nil, 200},
		{"GET", "/favicon.svg", nil, 200},
		{"GET", "/approvals/abc", nil, 200},
		{"GET", "/assets/gone-0.js", nil, 404},
		{"POST", "/", nil, 405},
		// Require's own refusals, written before any API handler runs.
		{"GET", "/api/me", nil, 401},
		{"GET", "/api/nothing-here", nil, 401},
		{"POST", "/api/logout", cookie, 403},
		{"POST", "/api/login", map[string]string{"Content-Type": "text/plain"}, 401},
		{"GET", "/api/me", cookie, 200},
		{"GET", "/api", nil, http.StatusTemporaryRedirect},
	} {
		resp, body := send(t, f, tc.method, tc.path, tc.hdr)
		if resp.StatusCode != tc.code {
			t.Errorf("%s %s: status %d, want %d: %s", tc.method, tc.path, resp.StatusCode, tc.code, body)
		}
		for k, v := range securityHeaders {
			if got := resp.Header.Get(k); got != v {
				t.Errorf("%s %s (%d): %s = %q, want %q", tc.method, tc.path, resp.StatusCode, k, got, v)
			}
		}
	}
}

func TestNoCORS(t *testing.T) {
	f := newServerFixture(t)
	c := f.signIn(t, "bob")
	origin := map[string]string{"Origin": "https://evil.example"}
	withCookie := map[string]string{"Origin": "https://evil.example", "Cookie": SessionCookie + "=" + c.cookie}
	preflight := map[string]string{"Origin": "https://evil.example", "Access-Control-Request-Method": "POST",
		"Access-Control-Request-Headers": CSRFHeader}
	for _, tc := range []struct {
		method, path string
		hdr          map[string]string
	}{
		{"GET", "/", origin},
		{"GET", "/api/me", origin},
		{"GET", "/api/me", withCookie},
		{"GET", "/api/approvals", withCookie},
		{"OPTIONS", "/api/approvals/0123456789abcdef0123456789abcdef/approve", preflight},
		{"OPTIONS", "/api/login", preflight},
	} {
		resp, _ := send(t, f, tc.method, tc.path, tc.hdr)
		for k := range resp.Header {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("%s %s: %s: %q", tc.method, tc.path, k, resp.Header.Get(k))
			}
		}
	}
}

func TestSPAFallback(t *testing.T) {
	f := newServerFixture(t)
	for _, tc := range []struct {
		path, want, ctype string
		code              int
	}{
		{"/", testIndex, "text/html", 200},
		{"/approvals", testIndex, "text/html", 200},
		{"/approvals/0123456789abcdef0123456789abcdef", testIndex, "text/html", 200},
		// A directory is a client route, never a listing.
		{"/assets/", testIndex, "text/html", 200},
		{"/assets/app-1.js", `console.log("ui")`, "text/javascript", 200},
		{"/favicon.svg", `<svg xmlns="http://www.w3.org/2000/svg"/>`, "image/svg+xml", 200},
		// A name with a dot is a file: a missing one is a 404, not HTML
		// that a <script> tag would then be handed.
		{"/assets/app-0.js", "", "", 404},
		{"/robots.txt", "", "", 404},
	} {
		resp, body := send(t, f, "GET", tc.path, nil)
		if resp.StatusCode != tc.code {
			t.Errorf("%s: status %d, want %d", tc.path, resp.StatusCode, tc.code)
			continue
		}
		if tc.code != 200 {
			if strings.Contains(body, "<script") {
				t.Errorf("%s: a miss came back as the app: %s", tc.path, body)
			}
			continue
		}
		if body != tc.want || !strings.HasPrefix(resp.Header.Get("Content-Type"), tc.ctype) {
			t.Errorf("%s: %s %q, want %s %q", tc.path, resp.Header.Get("Content-Type"), body, tc.ctype, tc.want)
		}
	}
	// index.html revalidates, so an upgrade's new bundle names are seen.
	if resp, _ := send(t, f, "GET", "/approvals", nil); resp.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("index.html Cache-Control = %q, want no-cache", resp.Header.Get("Cache-Control"))
	}
	if resp, body := send(t, f, "HEAD", "/", nil); resp.StatusCode != 200 || body != "" {
		t.Errorf("HEAD /: %d %q", resp.StatusCode, body)
	}
}

func TestAPIIsNoStore(t *testing.T) {
	f := newServerFixture(t)
	c := f.signIn(t, "bob")
	cookie := map[string]string{"Cookie": SessionCookie + "=" + c.cookie}
	for _, tc := range []struct {
		method, path string
		hdr          map[string]string
		code         int
	}{
		{"GET", "/api/me", nil, 401},
		{"GET", "/api/me", cookie, 200},
		{"GET", "/api/nothing-here", cookie, 404},
		{"GET", "/api/approvals/not-an-id", cookie, 404},
		{"POST", "/api/logout", cookie, 403},
		{"POST", "/api/login", nil, 401},
		{"GET", "/api", nil, http.StatusTemporaryRedirect},
	} {
		resp, _ := send(t, f, tc.method, tc.path, tc.hdr)
		if resp.StatusCode != tc.code || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s: %d Cache-Control %q, want %d no-store", tc.method, tc.path, resp.StatusCode,
				resp.Header.Get("Cache-Control"), tc.code)
		}
	}
	// Static files are not /api: the bundle may be cached.
	if resp, _ := send(t, f, "GET", "/assets/app-1.js", nil); resp.Header.Get("Cache-Control") == "no-store" {
		t.Error("a static asset was marked no-store")
	}
}

// The stream needs Flush and per-write deadlines from the connection
// itself; through the full handler (headers and all) hello still arrives
// at once, not when some buffer fills.
func TestStreamThroughNewServer(t *testing.T) {
	fastStream(t, 20*time.Millisecond, time.Hour)
	f := newServerFixture(t)
	c := f.signIn(t, "bob")
	resp, ch := openStream(t, c)
	if resp.StatusCode != 200 {
		t.Fatalf("stream status %d", resp.StatusCode)
	}
	if ev := next(t, ch, 2*time.Second); ev.name != "hello" {
		t.Fatalf("first event %q, want hello", ev.name)
	}
	for k, v := range securityHeaders {
		if resp.Header.Get(k) != v {
			t.Errorf("stream %s = %q", k, resp.Header.Get(k))
		}
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("stream Cache-Control = %q", resp.Header.Get("Cache-Control"))
	}
	appendRow(t, f, "r-through-server")
	for {
		ev := next(t, ch, 2*time.Second)
		if ev.name == "approvals" {
			continue
		}
		if ev.name != "audit" || !strings.Contains(ev.data, "r-through-server") {
			t.Errorf("event %q %s, want the new audit row", ev.name, ev.data)
		}
		break
	}
}
