package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
func harness(t *testing.T, h http.HandlerFunc) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	up := httptest.NewUnstartedServer(h)
	up.EnableHTTP2 = true
	up.StartTLS()
	t.Cleanup(up.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: up.Certificate().Raw})
	u, err := upstream.FromConfig(&rest.Config{Host: up.URL, BearerToken: "sa-token", TLSClientConfig: rest.TLSClientConfig{CAData: ca}})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	px := httptest.NewServer(New(fakeAuth{}, u, slog.New(slog.NewJSONHandler(&logs, nil))))
	t.Cleanup(px.Close)
	return px, &logs
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
	px, _ := harness(t, func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	})
	res := get(t, px.URL+"/api", "bg_good", nil)
	if res.StatusCode != 502 {
		t.Errorf("status %d, want 502", res.StatusCode)
	}
	status(t, res)
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
