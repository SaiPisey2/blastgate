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
	"k8s.io/client-go/rest"

	"github.com/SaiPisey2/blastgate/internal/session"
	"github.com/SaiPisey2/blastgate/internal/store"
	"github.com/SaiPisey2/blastgate/internal/upstream"
)

type fakeAuth struct{}

func (fakeAuth) Authenticate(r *http.Request) (store.Session, error) {
	if r.Header.Get("Authorization") == "Bearer bg_good" {
		return store.Session{ID: "sess-1", Human: "alice", Agent: "coding-agent"}, nil
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
	px := httptest.NewServer(New(auth, u, slog.New(slog.NewJSONHandler(logs, nil))))
	t.Cleanup(px.Close)
	return px, logs
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
	px, _ := harness(t, func(w http.ResponseWriter, r *http.Request) {
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
	for _, leak := range []string{"SECRET-PASSWORD", "bg_good", "sa-token", "command="} {
		if strings.Contains(logs.String(), leak) {
			t.Errorf("log contains %q:\n%s", leak, logs.String())
		}
	}
	if !strings.Contains(logs.String(), `"human":"alice"`) || !strings.Contains(logs.String(), "/exec") {
		t.Errorf("log lacks who and what:\n%s", logs.String())
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
