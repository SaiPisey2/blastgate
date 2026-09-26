package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/rest"

	"github.com/SaiPisey2/blastgate/internal/gate"
	"github.com/SaiPisey2/blastgate/internal/session"
	"github.com/SaiPisey2/blastgate/internal/store"
	"github.com/SaiPisey2/blastgate/internal/upstream"
)

type fakeAuth struct{}

func (fakeAuth) Authenticate(r *http.Request) (store.Session, error) {
	switch r.Header.Get("Authorization") {
	case "Bearer bg_good":
		return store.Session{ID: "sess-1", Human: "alice", Agent: "coding-agent"}, nil
	case "Bearer bg_nohuman":
		return store.Session{ID: "sess-2", Agent: "coding-agent"}, nil
	}
	return store.Session{}, session.ErrUnauthenticated
}

// harness returns a proxy server in front of an h2-capable TLS upstream
// running h, plus the log the proxy writes.
func harness(t *testing.T, h http.HandlerFunc) (*httptest.Server, *syncBuffer) {
	return harnessWith(t, fakeAuth{}, "", h)
}

// harnessWith takes the authenticator and an upstream path prefix, the
// shape of an API server reached through a gateway such as Rancher's.
func harnessWith(t *testing.T, auth Authenticator, prefix string, h http.HandlerFunc) (*httptest.Server, *syncBuffer) {
	t.Helper()
	return harnessDecider(t, auth, allowAll(), prefix, h)
}

// harnessDecider also takes the gate, for the tests of the decision step.
func harnessDecider(t *testing.T, auth Authenticator, d Decider, prefix string, h http.HandlerFunc) (*httptest.Server, *syncBuffer) {
	t.Helper()
	up := httptest.NewUnstartedServer(h)
	up.EnableHTTP2 = true
	up.StartTLS()
	t.Cleanup(up.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.Certificate().Raw})
	u, err := upstream.FromConfig(&rest.Config{Host: up.URL + prefix, BearerToken: "sa-token", TLSClientConfig: rest.TLSClientConfig{CAData: ca}})
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	px := httptest.NewServer(New(auth, d, u, slog.New(slog.NewJSONHandler(logs, nil))))
	t.Cleanup(px.Close)
	return px, logs
}

// recordingDecider is the gate stand-in. The mutex is there because
// Complete for a forwarded request runs after the response has reached
// the client, on the handler's goroutine, while the test reads.
type recordingDecider struct {
	mu        sync.Mutex
	verdict   gate.Verdict
	decided   []string
	completed []int
	outcomes  []string
	bodies    [][]byte
}

func (d *recordingDecider) Decide(_ context.Context, _ store.Session, r *http.Request, body []byte) gate.Verdict {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.decided = append(d.decided, r.Method+" "+r.URL.Path)
	d.bodies = append(d.bodies, body)
	return d.verdict
}

func (d *recordingDecider) Complete(_ context.Context, _ gate.Verdict, status int, outcome string, _ time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.completed = append(d.completed, status)
	d.outcomes = append(d.outcomes, outcome)
}

func (d *recordingDecider) snapshot() (decided []string, completed []int, outcomes []string, bodies [][]byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.decided...), append([]int(nil), d.completed...),
		append([]string(nil), d.outcomes...), append([][]byte(nil), d.bodies...)
}

// waitCompleted polls until Complete has been called n times, then waits
// a little longer so a second, wrong call would be seen too.
func (d *recordingDecider) waitCompleted(t *testing.T, n int) ([]int, []string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, c, _, _ := d.snapshot(); len(c) >= n {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	_, c, o, _ := d.snapshot()
	return c, o
}

func allowAll() *recordingDecider {
	return &recordingDecider{verdict: gate.Verdict{Forward: true}}
}

// syncBuffer is the proxy's log sink. Some tests read it while a handler
// goroutine may still be writing, after the client has gone away.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitFor polls the log until it holds want, because the lines tested here
// are written after the client has already stopped listening.
func waitFor(t *testing.T, logs *syncBuffer, want string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s := logs.String(); strings.Contains(s, want) {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("log never contained %s:\n%s", want, logs.String())
	return ""
}

// line returns the first log line containing msg.
func line(logs, msg string) string {
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, msg) {
			return l
		}
	}
	return ""
}

func get(t *testing.T, url, token string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func status(t *testing.T, res *http.Response) metav1.Status {
	t.Helper()
	defer res.Body.Close()
	var st metav1.Status
	if err := json.NewDecoder(res.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Kind != "Status" || st.APIVersion != "v1" {
		t.Errorf("not a Status object: %+v", st)
	}
	return st
}

func TestForwardsAsTheSessionHuman(t *testing.T) {
	var got http.Header
	px, _ := harness(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		fmt.Fprint(w, `{"kind":"APIVersions"}`)
	})
	res := get(t, px.URL+"/api", "bg_good", nil)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	want := map[string]string{
		"Impersonate-User": "alice",
		HeaderAgent:        "coding-agent",
		HeaderSession:      "sess-1",
		"Authorization":    "Bearer sa-token",
	}
	for k, v := range want {
		if got.Get(k) != v {
			t.Errorf("upstream %s = %q, want %q", k, got.Get(k), v)
		}
	}
}

func TestRejectsMissingOrBadTokens(t *testing.T) {
	called := false
	px, _ := harness(t, func(http.ResponseWriter, *http.Request) { called = true })
	for _, tok := range []string{"", "bg_bad"} {
		res := get(t, px.URL+"/api", tok, nil)
		if res.StatusCode != 401 {
			t.Errorf("token %q: status %d, want 401", tok, res.StatusCode)
		}
		if st := status(t, res); st.Reason != metav1.StatusReasonUnauthorized {
			t.Errorf("reason = %q", st.Reason)
		}
	}
	if called {
		t.Error("an unauthenticated request reached the upstream")
	}
}

// Raw bytes, so Go's client-side header canonicalisation cannot mask a
// server-side check that only matches the canonical spelling.
func TestRejectsClientImpersonationInAnyCase(t *testing.T) {
	called := false
	px, _ := harness(t, func(http.ResponseWriter, *http.Request) { called = true })
	addr := strings.TrimPrefix(px.URL, "http://")
	for _, h := range []string{
		"Impersonate-User: system:admin",
		"impersonate-user: system:admin",
		"IMPERSONATE-GROUP: system:masters",
		"Impersonate-Extra-Scopes: x",
		"Impersonate-Uid: 1",
		"X-Remote-User: root",
		"x-remote-extra-foo: bar",
	} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "GET /api HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer bg_good\r\n%s\r\nConnection: close\r\n\r\n", h)
		res, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != 403 {
			t.Errorf("%q: status %d, want 403", h, res.StatusCode)
		}
		res.Body.Close()
		conn.Close()
	}
	if called {
		t.Error("a request carrying impersonation reached the upstream")
	}
}

func TestStreamingResponsesAreFlushed(t *testing.T) {
	release := make(chan struct{})
	px, _ := harness(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"type":"ADDED"}`)
		w.(http.Flusher).Flush()
		<-release
	})
	defer close(release)
	res := get(t, px.URL+"/api/v1/pods?watch=true", "bg_good", nil)
	defer res.Body.Close()
	line := make(chan string, 1)
	go func() {
		l, _ := bufio.NewReader(res.Body).ReadString('\n')
		line <- l
	}()
	select {
	case l := <-line:
		if !strings.Contains(l, "ADDED") {
			t.Errorf("line = %q", l)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the first watch event was buffered instead of flushed")
	}
}

func TestUpgradeIsPassedThrough(t *testing.T) {
	var proto int
	px, logs := harness(t, func(w http.ResponseWriter, r *http.Request) {
		proto = r.ProtoMajor
		if r.Header.Get("Upgrade") != "SPDY/3.1" {
			http.Error(w, "no upgrade", 400)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n")
		brw.Flush()
		buf := make([]byte, 4)
		io.ReadFull(brw, buf)
		brw.Write(buf)
		brw.Flush()
	})
	conn, err := net.Dial("tcp", strings.TrimPrefix(px.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "POST /api/v1/namespaces/demo/pods/web/exec?command=sh HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer bg_good\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n")
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 101 {
		t.Fatalf("status %d, want 101", res.StatusCode)
	}
	conn.Write([]byte("ping"))
	buf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Errorf("echo = %q, %v", buf, err)
	}
	if proto != 1 {
		t.Errorf("upgrade reached the upstream over HTTP/%d", proto)
	}
	// The 101 goes to the hijacked connection, not through WriteHeader;
	// the log once called every exec and port-forward a 200.
	conn.Close()
	req := line(waitFor(t, logs, `"msg":"request"`), `"msg":"request"`)
	if !strings.Contains(req, `"status":101`) {
		t.Errorf("an upgraded request was not logged as 101:\n%s", req)
	}
}

func TestUpstreamFailureIsAStatus(t *testing.T) {
	// ErrAbortHandler resets the stream under both HTTP/1.1 and HTTP/2;
	// hijacking would not work here, since the normal transport speaks h2.
	// The prefix makes the forwarded path differ from the client's; both
	// log lines must name the path the client asked for.
	px, logs := harnessWith(t, fakeAuth{}, "/k8s/clusters/c-1", func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	})
	res := get(t, px.URL+"/api/v1/namespaces/demo/pods/web/exec?command=SECRET", "bg_good", nil)
	if res.StatusCode != 502 {
		t.Errorf("status %d, want 502", res.StatusCode)
	}
	status(t, res)
	all := waitFor(t, logs, `"msg":"request"`)
	if strings.Contains(all, "SECRET") || strings.Contains(all, "command=") {
		t.Errorf("an upstream failure logged the query string:\n%s", all)
	}
	errLine := line(all, `"msg":"upstream error"`)
	for _, want := range []string{`"session":"sess-1"`, `"human":"alice"`, `"agent":"coding-agent"`, `"method":"GET"`, `"path":"/api/v1/namespaces/demo/pods/web/exec"`} {
		if !strings.Contains(errLine, want) {
			t.Errorf("upstream error line lacks %s:\n%s", want, all)
		}
	}
	if !strings.Contains(line(all, `"msg":"request"`), `"path":"/api/v1/namespaces/demo/pods/web/exec"`) {
		t.Errorf("request line path is not the client's:\n%s", all)
	}
}

func TestLogsCarryNoTokenAndNoQuery(t *testing.T) {
	px, logs := harness(t, func(w http.ResponseWriter, r *http.Request) {})
	res := get(t, px.URL+"/api/v1/namespaces/demo/pods/web/exec?command=psql&command=-c&command=SECRET-PASSWORD", "bg_good", nil)
	res.Body.Close()
	// The request line is written after the response has gone out, so the
	// client can get here first: wait for it rather than read at once.
	all := waitFor(t, logs, `"msg":"request"`)
	for _, leak := range []string{"SECRET-PASSWORD", "bg_good", "sa-token", "command="} {
		if strings.Contains(all, leak) {
			t.Errorf("log contains %q:\n%s", leak, all)
		}
	}
	if !strings.Contains(all, `"human":"alice"`) || !strings.Contains(all, "/exec") {
		t.Errorf("log lacks who and what:\n%s", all)
	}
}

// http.Server runs ReverseProxy, which panics with ErrAbortHandler when
// the client leaves mid-stream. A log call placed after the proxy is
// skipped by that panic, and every watch or logs -f a client stops would
// vanish from the record.
func TestStreamEndedByClientIsStillLogged(t *testing.T) {
	release := make(chan struct{})
	px, logs := harness(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"type":"ADDED"}`)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	conn, err := net.Dial("tcp", strings.TrimPrefix(px.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "GET /api/v1/pods?watch=true HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer bg_good\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if l, err := bufio.NewReader(res.Body).ReadString('\n'); err != nil || !strings.Contains(l, "ADDED") {
		t.Fatalf("first event = %q, %v", l, err)
	}
	conn.Close()
	req := line(waitFor(t, logs, `"msg":"request"`), `"msg":"request"`)
	for _, want := range []string{`"human":"alice"`, `"aborted":true`} {
		if !strings.Contains(req, want) {
			t.Errorf("request line lacks %s: %s", want, req)
		}
	}
}

// A client that gives up before the response says nothing about whether
// the API server acted: a create may already be committed. Recording it
// as a 502 would claim a failure that may not have happened.
func TestClientCancelIsOutcomeUnknown(t *testing.T) {
	arrived, release := make(chan struct{}), make(chan struct{})
	px, logs := harness(t, func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", px.URL+"/api/v1/namespaces/demo/pods", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer bg_good")
	go func() {
		<-arrived
		cancel()
	}()
	if res, err := http.DefaultClient.Do(req); err == nil {
		res.Body.Close()
		t.Fatal("the request completed; the cancel did not happen")
	}
	all := waitFor(t, logs, `"msg":"request"`)
	if strings.Contains(all, `"msg":"upstream error"`) {
		t.Errorf("a client cancel was logged as an upstream failure:\n%s", all)
	}
	for _, msg := range []string{`"msg":"client cancelled; outcome unknown"`, `"msg":"request"`} {
		l := line(all, msg)
		for _, want := range []string{`"session":"sess-1"`, `"human":"alice"`, `"agent":"coding-agent"`, `"method":"POST"`, "outcome unknown"} {
			if !strings.Contains(l, want) {
				t.Errorf("%s line lacks %s:\n%s", msg, want, all)
			}
		}
	}
	if strings.Contains(line(all, `"msg":"request"`), `"status":502`) {
		t.Errorf("request line claims a 502:\n%s", all)
	}
}

type brokenAuth struct{}

func (brokenAuth) Authenticate(*http.Request) (store.Session, error) {
	return store.Session{}, errors.New("database is locked")
}

// A store failure is not the caller's fault; 401 would tell kubectl to
// re-authenticate with a token that is in fact valid.
func TestSessionLookupFailureIsUnavailable(t *testing.T) {
	called := false
	px, _ := harnessWith(t, brokenAuth{}, "", func(http.ResponseWriter, *http.Request) { called = true })
	res := get(t, px.URL+"/api", "bg_good", nil)
	if res.StatusCode != 503 {
		t.Errorf("status %d, want 503", res.StatusCode)
	}
	if st := status(t, res); st.Reason != metav1.StatusReasonServiceUnavailable {
		t.Errorf("reason = %q", st.Reason)
	}
	if called {
		t.Error("a request with no session reached the upstream")
	}
}

func TestImpersonationRefusalIsAForbiddenStatusAndLogsNoValue(t *testing.T) {
	px, logs := harness(t, func(http.ResponseWriter, *http.Request) {})
	res := get(t, px.URL+"/api", "bg_good", map[string]string{"Impersonate-User": "system:admin"})
	if res.StatusCode != 403 {
		t.Errorf("status %d, want 403", res.StatusCode)
	}
	if st := status(t, res); st.Reason != metav1.StatusReasonForbidden {
		t.Errorf("reason = %q", st.Reason)
	}
	all := waitFor(t, logs, `"msg":"refused client impersonation"`)
	if strings.Contains(all, "system:admin") {
		t.Errorf("the refusal logged the header's value:\n%s", all)
	}
}

// A declared trailer is a header that arrives after the body, and
// ReverseProxy forwards trailers. Checking only the headers would let an
// impersonation header in at the end of a chunked request.
func TestRejectsImpersonationDeclaredAsATrailer(t *testing.T) {
	called := false
	px, _ := harness(t, func(http.ResponseWriter, *http.Request) { called = true })
	addr := strings.TrimPrefix(px.URL, "http://")
	for _, req := range []string{
		"Transfer-Encoding: chunked\r\nTrailer: Impersonate-User\r\n\r\n0\r\nImpersonate-User: system:admin\r\n\r\n",
		"Transfer-Encoding: chunked\r\ntrailer: content-md5, impersonate-group\r\n\r\n0\r\nimpersonate-group: system:masters\r\n\r\n",
		"Transfer-Encoding: chunked\r\nTrailer: X-REMOTE-USER\r\n\r\n0\r\n\r\n",
		// Without chunking the server keeps Trailer as an ordinary header.
		"Content-Length: 0\r\nTrailer: Impersonate-Uid\r\n\r\n",
	} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "POST /api HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer bg_good\r\nConnection: close\r\n%s", req)
		res, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != 403 {
			t.Errorf("%q: status %d, want 403", req, res.StatusCode)
		}
		res.Body.Close()
		conn.Close()
	}
	if called {
		t.Error("a request declaring an impersonation trailer reached the upstream")
	}
}

// When the upstream breaks mid-stream, ReverseProxy panics with
// ErrAbortHandler and the logging defer must hand that panic back to
// http.Server. Swallowing it would end the chunked body cleanly, and a
// truncated watch or log would look complete to kubectl.
func TestUpstreamAbortMidStreamReachesTheClient(t *testing.T) {
	px, _ := harness(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"type":"ADDED"}`)
		w.(http.Flusher).Flush()
		time.Sleep(50 * time.Millisecond)
		panic(http.ErrAbortHandler)
	})
	res := get(t, px.URL+"/api/v1/pods?watch=true", "bg_good", nil)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err == nil {
		t.Errorf("a stream the upstream broke read as complete: %q", body)
	}
}

// kubectl reads a failed discovery response with Raw(), which never decodes
// the Status body, so a refusal's message reaches the user only through a
// Warning header. Discovery is the first request kubectl makes, and --as
// puts impersonation headers on it too.
func TestRefusalsCarryTheirMessageAsAWarning(t *testing.T) {
	px, _ := harness(t, func(http.ResponseWriter, *http.Request) {})
	for name, res := range map[string]*http.Response{
		"unauthenticated": get(t, px.URL+"/api", "bg_bad", nil),
		"impersonation":   get(t, px.URL+"/api", "bg_good", map[string]string{"Impersonate-User": "system:admin"}),
	} {
		st := status(t, res)
		ws, errs := utilnet.ParseWarningHeaders(res.Header.Values("Warning"))
		if len(errs) > 0 || len(ws) != 1 || ws[0].Code != 299 || ws[0].Text != st.Message {
			t.Errorf("%s: warnings %+v (errors %v), want one 299 carrying %q", name, ws, errs, st.Message)
		}
	}
}

// A refused token is logged -- guessing, or an agent still using a revoked
// session, must be visible -- but the token itself never is, nor the query.
func TestUnauthenticatedRequestsAreLoggedWithoutTheToken(t *testing.T) {
	px, logs := harness(t, func(http.ResponseWriter, *http.Request) {})
	res := get(t, px.URL+"/api/v1/namespaces/demo/pods?labelSelector=secret-query", "bg_stolen-token-value", nil)
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatalf("status %d, want 401", res.StatusCode)
	}
	l := line(waitFor(t, logs, `"msg":"unauthenticated"`), `"msg":"unauthenticated"`)
	for _, want := range []string{`"method":"GET"`, `"path":"/api/v1/namespaces/demo/pods"`, `"remote":"127.0.0.1:`} {
		if !strings.Contains(l, want) {
			t.Errorf("unauthenticated line lacks %s:\n%s", want, l)
		}
	}
	for _, leak := range []string{"stolen-token-value", "Bearer", "secret-query"} {
		if strings.Contains(logs.String(), leak) {
			t.Errorf("log contains %q:\n%s", leak, logs.String())
		}
	}
}

func TestSessionLookupFailureNamesTheRequest(t *testing.T) {
	px, logs := harnessWith(t, brokenAuth{}, "", func(http.ResponseWriter, *http.Request) {})
	get(t, px.URL+"/api/v1/pods?watch=1", "bg_good", nil).Body.Close()
	l := line(waitFor(t, logs, `"msg":"session lookup failed"`), `"msg":"session lookup failed"`)
	if !strings.Contains(l, `"method":"GET"`) || !strings.Contains(l, `"path":"/api/v1/pods"`) || strings.Contains(l, "watch=1") {
		t.Errorf("lookup failure line:\n%s", l)
	}
}

// An empty Impersonate-User is not impersonation: the API server would
// act as blastgate's own service account. Whatever produced such a
// session, it must never be forwarded.
func TestASessionWithNoHumanIsNeverForwarded(t *testing.T) {
	called := false
	px, _ := harness(t, func(http.ResponseWriter, *http.Request) { called = true })
	res := get(t, px.URL+"/api", "bg_nohuman", nil)
	if res.StatusCode != 503 {
		t.Errorf("status %d, want 503", res.StatusCode)
	}
	if st := status(t, res); st.Reason != metav1.StatusReasonServiceUnavailable {
		t.Errorf("reason = %q", st.Reason)
	}
	if called {
		t.Error("a session with no human reached the upstream")
	}
}

// The refusal is the gate's; the proxy only has to deliver it the way
// kubectl can print it, and never let the request through.
func TestRefusedVerdictIsWrittenAsAStatusAndNotForwarded(t *testing.T) {
	d := &recordingDecider{verdict: gate.Verdict{Forward: false, Code: 403, Reason: metav1.StatusReasonForbidden, Message: "blastgate: held for approval abc", Ticket: "abc"}}
	called := false
	px, logs := harnessDecider(t, fakeAuth{}, d, "", func(http.ResponseWriter, *http.Request) { called = true })
	req, _ := http.NewRequest("DELETE", px.URL+"/api/v1/namespaces/demo/pods/web", nil)
	req.Header.Set("Authorization", "Bearer bg_good")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 403 {
		t.Errorf("status %d, want 403", res.StatusCode)
	}
	st := status(t, res)
	if st.Message != "blastgate: held for approval abc" || st.Reason != metav1.StatusReasonForbidden || st.Code != 403 {
		t.Errorf("status = %+v", st)
	}
	ws, errs := utilnet.ParseWarningHeaders(res.Header.Values("Warning"))
	if len(errs) > 0 || len(ws) != 1 || ws[0].Text != st.Message {
		t.Errorf("warnings %+v (errors %v), want one carrying %q", ws, errs, st.Message)
	}
	if called {
		t.Error("a refused request reached the upstream")
	}
	if c, _ := d.waitCompleted(t, 1); len(c) != 1 || c[0] != 403 {
		t.Errorf("completed = %v, want [403]", c)
	}
	l := line(waitFor(t, logs, `"msg":"refused"`), `"msg":"refused"`)
	for _, want := range []string{`"session":"sess-1"`, `"human":"alice"`, `"agent":"coding-agent"`, `"method":"DELETE"`, `"path":"/api/v1/namespaces/demo/pods/web"`, `"code":403`, `"ticket":"abc"`} {
		if !strings.Contains(l, want) {
			t.Errorf("refused line lacks %s:\n%s", want, logs.String())
		}
	}
}

// The gate scores the bytes it is given; if the upstream received any
// others, what was approved would not be what ran.
func TestBodyReachesDeciderAndUpstreamIntact(t *testing.T) {
	d := allowAll()
	var got []byte
	var gotLen int64
	px, _ := harnessDecider(t, fakeAuth{}, d, "", func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		gotLen = r.ContentLength
	})
	body := `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"web"},"spec":{"replicas":0}}`
	req, _ := http.NewRequest("PUT", px.URL+"/apis/apps/v1/namespaces/demo/deployments/web", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer bg_good")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	_, _, _, bodies := d.snapshot()
	if len(bodies) != 1 || string(bodies[0]) != body {
		t.Errorf("decider saw %q, want %q", bodies, body)
	}
	if string(got) != body || gotLen != int64(len(body)) {
		t.Errorf("upstream read %q (length %d), want %q", got, gotLen, body)
	}
}

// A chunked body (no Content-Length, as kubectl streams some requests) is
// buffered whole: the decider scores every byte, and the upstream gets the
// same bytes with their length declared, so nothing can arrive after the
// decision that the decision did not see.
func TestChunkedBodyReachesDeciderAndUpstreamIntact(t *testing.T) {
	d := allowAll()
	var got []byte
	var gotLen int64
	var gotTE []string
	px, _ := harnessDecider(t, fakeAuth{}, d, "", func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		gotLen, gotTE = r.ContentLength, r.TransferEncoding
	})
	body := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"settings"},"data":{"k":"` + strings.Repeat("v", 64<<10) + `"}}`
	// MultiReader hides the length, so the client sends it chunked.
	req, _ := http.NewRequest("POST", px.URL+"/api/v1/namespaces/demo/configmaps", io.MultiReader(strings.NewReader(body)))
	req.Header.Set("Authorization", "Bearer bg_good")
	if req.ContentLength != 0 {
		t.Fatalf("request declares length %d; the test needs a chunked body", req.ContentLength)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	_, _, _, bodies := d.snapshot()
	if len(bodies) != 1 || string(bodies[0]) != body {
		t.Errorf("decider saw %d bodies (first %d bytes), want one of %d bytes", len(bodies), lenFirst(bodies), len(body))
	}
	if string(got) != body || gotLen != int64(len(body)) || len(gotTE) != 0 {
		t.Errorf("upstream read %d bytes, ContentLength %d, Transfer-Encoding %v; want %d bytes with that length, not chunked", len(got), gotLen, gotTE, len(body))
	}
}

func lenFirst(b [][]byte) int {
	if len(b) == 0 {
		return -1
	}
	return len(b[0])
}

// A chunked body has no declared length, so the limit has to be on what is
// read, not on Content-Length.
func TestOversizedBodyIsRefused(t *testing.T) {
	for name, chunked := range map[string]bool{"content-length": false, "chunked": true} {
		t.Run(name, func(t *testing.T) {
			d := allowAll()
			called := false
			px, _ := harnessDecider(t, fakeAuth{}, d, "", func(http.ResponseWriter, *http.Request) { called = true })
			var body io.Reader = bytes.NewReader(make([]byte, 3<<20+1))
			if chunked {
				body = io.MultiReader(body) // hides the length, so the client chunks
			}
			req, _ := http.NewRequest("POST", px.URL+"/api/v1/namespaces/demo/configmaps", body)
			req.Header.Set("Authorization", "Bearer bg_good")
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != 413 {
				t.Errorf("status %d, want 413", res.StatusCode)
			}
			if st := status(t, res); st.Reason != metav1.StatusReasonRequestEntityTooLarge {
				t.Errorf("status = %+v", st)
			}
			if decided, _, _, _ := d.snapshot(); len(decided) != 0 {
				t.Errorf("decider was asked about an oversized body: %v", decided)
			}
			if called {
				t.Error("an oversized body reached the upstream")
			}
		})
	}
}

// Exactly 3 MiB is the API server's own limit and must still pass.
func TestBodyAtTheLimitIsForwarded(t *testing.T) {
	d := allowAll()
	var n int
	px, _ := harnessDecider(t, fakeAuth{}, d, "", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		n = len(b)
	})
	req, _ := http.NewRequest("POST", px.URL+"/api/v1/namespaces/demo/configmaps", bytes.NewReader(make([]byte, 3<<20)))
	req.Header.Set("Authorization", "Bearer bg_good")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || n != 3<<20 {
		t.Errorf("status %d, upstream read %d bytes; want 200 and %d", res.StatusCode, n, 3<<20)
	}
}

func TestCompleteIsCalledOnceForAForwardedRequest(t *testing.T) {
	d := allowAll()
	px, _ := harnessDecider(t, fakeAuth{}, d, "", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	req, _ := http.NewRequest("POST", px.URL+"/api/v1/namespaces/demo/configmaps", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer bg_good")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	c, o := d.waitCompleted(t, 1)
	if len(c) != 1 || c[0] != http.StatusCreated || o[0] != "" {
		t.Errorf("completed = %v %q, want [201] with no outcome", c, o)
	}
	if decided, _, _, _ := d.snapshot(); len(decided) != 1 || decided[0] != "POST /api/v1/namespaces/demo/configmaps" {
		t.Errorf("decided = %v", decided)
	}
}

// The panic ReverseProxy raises for a stream the client left must not skip
// the result row, as it once skipped the log line.
func TestCompleteIsCalledForAnAbortedStream(t *testing.T) {
	d := allowAll()
	release := make(chan struct{})
	px, _ := harnessDecider(t, fakeAuth{}, d, "", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"type":"ADDED"}`)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	conn, err := net.Dial("tcp", strings.TrimPrefix(px.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "GET /api/v1/pods?watch=true HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer bg_good\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if l, err := bufio.NewReader(res.Body).ReadString('\n'); err != nil || !strings.Contains(l, "ADDED") {
		t.Fatalf("first event = %q, %v", l, err)
	}
	conn.Close()
	c, o := d.waitCompleted(t, 1)
	if len(c) != 1 || o[0] != "aborted" {
		t.Errorf("completed = %v %q, want one aborted", c, o)
	}
}

func TestCompleteIsCalledForACancelledRequest(t *testing.T) {
	d := allowAll()
	arrived, release := make(chan struct{}), make(chan struct{})
	px, _ := harnessDecider(t, fakeAuth{}, d, "", func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", px.URL+"/api/v1/namespaces/demo/pods", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer bg_good")
	go func() {
		<-arrived
		cancel()
	}()
	if res, err := http.DefaultClient.Do(req); err == nil {
		res.Body.Close()
		t.Fatal("the request completed; the cancel did not happen")
	}
	c, o := d.waitCompleted(t, 1)
	if len(c) != 1 || c[0] != 0 || o[0] != "client cancelled; outcome unknown" {
		t.Errorf("completed = %v %q, want [0] with outcome unknown", c, o)
	}
}

// Trailers arrive after the body, and Go keeps undeclared ones. Now the
// body is read before forwarding, ReverseProxy would copy such a trailer
// into the outgoing request, so the check has to run again after reading.
func TestRejectsUndeclaredImpersonationTrailer(t *testing.T) {
	d := allowAll()
	called := false
	px, _ := harnessDecider(t, fakeAuth{}, d, "", func(http.ResponseWriter, *http.Request) { called = true })
	conn, err := net.Dial("tcp", strings.TrimPrefix(px.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "POST /api/v1/namespaces/demo/configmaps HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer bg_good\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nImpersonate-User: system:admin\r\n\r\n")
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Errorf("status %d, want 403", res.StatusCode)
	}
	if called {
		t.Error("an undeclared impersonation trailer reached the upstream")
	}
	if decided, _, _, _ := d.snapshot(); len(decided) != 0 {
		t.Errorf("decider was asked about a request carrying impersonation: %v", decided)
	}
}

func TestNewPanicsWithoutADecider(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("New accepted a nil Decider")
		}
	}()
	New(fakeAuth{}, nil, &upstream.Upstream{}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
}

// A gate bug that refuses without a code must still refuse: WriteHeader
// panics on 0, and a 2xx would tell kubectl the write succeeded.
func TestRefusalWithoutACodeIsAnError(t *testing.T) {
	d := &recordingDecider{verdict: gate.Verdict{Forward: false}}
	called := false
	px, _ := harnessDecider(t, fakeAuth{}, d, "", func(http.ResponseWriter, *http.Request) { called = true })
	req, _ := http.NewRequest("DELETE", px.URL+"/api/v1/namespaces/demo/pods/web", nil)
	req.Header.Set("Authorization", "Bearer bg_good")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 503 || called {
		t.Errorf("status %d, upstream called %v; want 503 and not forwarded", res.StatusCode, called)
	}
	if c, _ := d.waitCompleted(t, 1); len(c) != 1 || c[0] != 503 {
		t.Errorf("completed = %v, want [503]", c)
	}
}
