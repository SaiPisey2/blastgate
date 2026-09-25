package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func writeUpstream(t *testing.T, srv *httptest.Server) string {
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["up"] = &clientcmdapi.Cluster{Server: srv.URL, CertificateAuthorityData: ca}
	cfg.AuthInfos["sa"] = &clientcmdapi.AuthInfo{Token: "sa-token"}
	cfg.Contexts["up"] = &clientcmdapi.Context{Cluster: "up", AuthInfo: "sa"}
	cfg.CurrentContext = "up"
	p := filepath.Join(t.TempDir(), "upstream.kubeconfig")
	if err := clientcmd.WriteToFile(*cfg, p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestServeRefusals(t *testing.T) {
	dir := t.TempDir()
	for name, m := range map[string]map[string]string{
		"no key":      {"BLASTGATE_DATA_DIR": dir, "BLASTGATE_UPSTREAM_KUBECONFIG": "/x"},
		"no upstream": {"BLASTGATE_DATA_DIR": dir, "BLASTGATE_SIGNING_KEY": "3f9a1c07d24be85f6a0913c7e2d84b5f70a6c31e9d28f4b1"},
		"remote":      {"BLASTGATE_DATA_DIR": dir, "BLASTGATE_SIGNING_KEY": "3f9a1c07d24be85f6a0913c7e2d84b5f70a6c31e9d28f4b1", "BLASTGATE_UPSTREAM_KUBECONFIG": "/x", "BLASTGATE_LISTEN": "0.0.0.0:8443"},
	} {
		t.Run(name, func(t *testing.T) {
			var errb syncBuf
			if code := serveCmd(context.Background(), func(k string) string { return m[k] }, &errb); code != 2 {
				t.Errorf("exit = %d, want 2: %s", code, errb.String())
			}
		})
	}
}

// startServe runs serveCmd with env until the test ends, and returns its
// log. It waits for serve to listen before returning.
func startServe(t *testing.T, env func(string) string) *syncBuf {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	logs := &syncBuf{}
	go func() { done <- serveCmd(ctx, env, logs) }()
	t.Cleanup(func() {
		cancel()
		select {
		case code := <-done:
			if code != 0 {
				t.Errorf("serve exit = %d after shutdown\n%s", code, logs.String())
			}
		case <-time.After(10 * time.Second):
			t.Error("serve did not shut down")
		}
	})
	// Wait for serve to listen before the client dials it. (Both paths
	// create the CA on first use; tlsutil makes that safe to race.)
	for i := 0; ; i++ {
		c, err := net.Dial("tcp", env("BLASTGATE_LISTEN"))
		if err == nil {
			c.Close()
			return logs
		}
		if i == 100 {
			t.Fatalf("serve never listened:\n%s", logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// sessionClient makes a session for alice and returns a client and host
// that reach serve with it.
func sessionClient(t *testing.T, env func(string) string) (*http.Client, string) {
	t.Helper()
	var kc, errb bytes.Buffer
	if code := run([]string{"session", "new", "--human", "alice", "--agent", "e2e"}, env, &kc, &errb); code != 0 {
		t.Fatalf("session new: %s", errb.String())
	}
	cfg, err := clientcmd.RESTConfigFromKubeConfig(kc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	client, err := rest.HTTPClientFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return client, cfg.Host
}

// A read is never scored or held: with the real gate wired in, GET /api
// still goes straight through, as alice.
func TestServeForwardsASessionEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var seenUser string
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		seenUser = r.Header.Get("Impersonate-User")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[]}`))
	}))
	defer up.Close()

	m := map[string]string{
		"BLASTGATE_DATA_DIR":            t.TempDir(),
		"BLASTGATE_LISTEN":              freeAddr(t),
		"BLASTGATE_SIGNING_KEY":         "3f9a1c07d24be85f6a0913c7e2d84b5f70a6c31e9d28f4b1",
		"BLASTGATE_UPSTREAM_KUBECONFIG": writeUpstream(t, up),
	}
	env := func(k string) string { return m[k] }
	logs := startServe(t, env)
	client, host := sessionClient(t, env)
	res, err := client.Get(host + "/api")
	if err != nil {
		t.Fatalf("never reached blastgate: %v\n%s", err, logs.String())
	}
	res.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if res.StatusCode != 200 || seenUser != "alice" {
		t.Errorf("status %d, upstream saw Impersonate-User %q", res.StatusCode, seenUser)
	}
	for _, want := range []string{`"msg":"listening"`, `"policy":"default"`, `"hold":"45s"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("start-up log lacks %s:\n%s", want, logs.String())
		}
	}
}

// The whole wiring, one write: an upstream that fails every dry-run leaves
// the write unmeasured, so it is held and ticketed; the pending approval
// can be approved from the CLI (it was created with a live expiry, P1-R16);
// and the agent's identical retry is released, re-scored, forwarded once.
func TestServeHoldsAWriteUntilApproved(t *testing.T) {
	var mu sync.Mutex
	var forwarded []string
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Query().Get("dryRun") != "":
			http.Error(w, "dry-run unavailable", http.StatusInternalServerError)
		case r.Method == "POST":
			mu.Lock()
			forwarded = append(forwarded, r.Header.Get("Impersonate-User")+" "+r.URL.Path)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"settings","namespace":"demo"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer up.Close()

	dir := t.TempDir()
	m := map[string]string{
		"BLASTGATE_DATA_DIR":            dir,
		"BLASTGATE_LISTEN":              freeAddr(t),
		"BLASTGATE_SIGNING_KEY":         "3f9a1c07d24be85f6a0913c7e2d84b5f70a6c31e9d28f4b1",
		"BLASTGATE_UPSTREAM_KUBECONFIG": writeUpstream(t, up),
		"BLASTGATE_HOLD":                "1s",
	}
	env := func(k string) string { return m[k] }
	logs := startServe(t, env)
	client, host := sessionClient(t, env)

	create := func() (int, string) {
		body := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"settings","namespace":"demo"}}`
		res, err := client.Post(host+"/api/v1/namespaces/demo/configmaps", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("never reached blastgate: %v\n%s", err, logs.String())
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}

	began := time.Now()
	code, msg := create()
	// BLASTGATE_HOLD reaches the gate: the ticket comes back after the 1s
	// window, not the 45s default.
	if waited := time.Since(began); waited < time.Second || waited > 10*time.Second {
		t.Errorf("the hold lasted %v, want about 1s", waited)
	}
	if code != http.StatusForbidden || !strings.Contains(msg, "held for approval") || !strings.Contains(msg, "unmeasured") {
		t.Fatalf("first create: %d %s", code, msg)
	}
	var list bytes.Buffer
	if c := run([]string{"approvals", "--status", "pending"}, env, &list, io.Discard); c != 0 {
		t.Fatal("approvals failed")
	}
	fields := strings.Fields(strings.SplitN(list.String(), "\n", 3)[1])
	if len(fields) == 0 || !strings.Contains(msg, fields[0]) {
		t.Fatalf("the ticket does not name the pending approval:\n%s\n%s", msg, list.String())
	}
	id := fields[0]
	mu.Lock()
	if len(forwarded) != 0 {
		t.Errorf("a held write reached the upstream: %v", forwarded)
	}
	mu.Unlock()

	var errb bytes.Buffer
	if c := run([]string{"approve", id, "--by", "bob"}, env, io.Discard, &errb); c != 0 {
		t.Fatalf("approve: exit %d: %s", c, errb.String())
	}
	if code, msg := create(); code != http.StatusCreated {
		t.Fatalf("retry after approval: %d %s", code, msg)
	}
	mu.Lock()
	if len(forwarded) != 1 || forwarded[0] != "alice /api/v1/namespaces/demo/configmaps" {
		t.Errorf("forwarded = %v, want exactly one create as alice", forwarded)
	}
	mu.Unlock()
	// Spent: the same request again needs a new approval.
	if code, msg := create(); code != http.StatusForbidden || strings.Contains(msg, id) {
		t.Errorf("second retry: %d %s; the spent approval must not release it again", code, msg)
	}

	// The trail holds the policy decision -- hold, with the approval that
	// released it -- for each of the three attempts.
	var out bytes.Buffer
	if c := run([]string{"audit", "export"}, env, &out, io.Discard); c != 0 {
		t.Fatal("audit export failed")
	}
	holds := 0
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.Contains(l, `"kind":"decision"`) && strings.Contains(l, `"decision":"hold"`) {
			holds++
		}
	}
	if holds != 3 {
		t.Errorf("%d hold decision rows, want 3:\n%s", holds, out.String())
	}
}
