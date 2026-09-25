package main

import (
	"bytes"
	"context"
	"encoding/pem"
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

func TestServeForwardsASessionEndToEnd(t *testing.T) {
	var seenUser string
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUser = r.Header.Get("Impersonate-User")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[]}`))
	}))
	defer up.Close()

	addr := freeAddr(t)
	m := map[string]string{
		"BLASTGATE_DATA_DIR":            t.TempDir(),
		"BLASTGATE_LISTEN":              addr,
		"BLASTGATE_SIGNING_KEY":         "3f9a1c07d24be85f6a0913c7e2d84b5f70a6c31e9d28f4b1",
		"BLASTGATE_UPSTREAM_KUBECONFIG": writeUpstream(t, up),
	}
	env := func(k string) string { return m[k] }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	var logs syncBuf
	go func() { done <- serveCmd(ctx, env, &logs) }()

	// Wait for serve to listen before minting a session: both create the CA
	// on first use, and racing them could leave the kubeconfig trusting a
	// CA the serving certificate was not issued by.
	for i := 0; ; i++ {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		if i == 100 {
			t.Fatalf("serve never listened:\n%s", logs.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

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
	res, err := client.Get(cfg.Host + "/api")
	if err != nil {
		t.Fatalf("never reached blastgate: %v\n%s", err, logs.String())
	}
	res.Body.Close()
	if res.StatusCode != 200 || seenUser != "alice" {
		t.Errorf("status %d, upstream saw Impersonate-User %q", res.StatusCode, seenUser)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("serve exit = %d after shutdown\n%s", code, logs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not shut down")
	}
	if !strings.Contains(logs.String(), "listening") {
		t.Errorf("no listening line:\n%s", logs.String())
	}
}
