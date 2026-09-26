package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SaiPisey2/blastgate/internal/tlsutil"
)

// listenerEnv is serveEnv with the admin (and, when webhook is true, the
// webhook) listener on free ports of its own.
func listenerEnv(t *testing.T, webhook bool, extra map[string]string) (func(string) string, map[string]string) {
	t.Helper()
	m := map[string]string{"BLASTGATE_ADMIN_LISTEN": freeAddr(t)}
	if webhook {
		m["BLASTGATE_WEBHOOK_LISTEN"] = freeAddr(t)
	}
	for k, v := range extra {
		m[k] = v
	}
	env := serveEnv(t, m)
	return env, map[string]string{
		"data":    env("BLASTGATE_DATA_DIR"),
		"admin":   env("BLASTGATE_ADMIN_LISTEN"),
		"webhook": env("BLASTGATE_WEBHOOK_LISTEN"),
	}
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	for i := 0; ; i++ {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return
		}
		if i == 100 {
			t.Fatalf("%s never listened", addr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// caClient trusts blastgate's own CA, as a browser that imported it does.
func caClient(t *testing.T, dataDir string, certs ...tls.Certificate) *http.Client {
	t.Helper()
	caPEM, err := tlsutil.LoadCA(filepath.Join(dataDir, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: certs}},
		// The header checks must see the answer to exactly this request.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func get(t *testing.T, c *http.Client, url string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

const wantCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

func TestServeAdminListener(t *testing.T) {
	env, a := listenerEnv(t, false, nil)
	logs := startServe(t, env)
	waitListening(t, a["admin"])
	c := caClient(t, a["data"])
	base := "https://" + a["admin"]

	resp, body := get(t, c, base+"/api/me")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/api/me without a session: %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Content-Security-Policy") != wantCSP || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("/api/me 401 headers: %v", resp.Header)
	}
	for _, path := range []string{"/", "/approvals/0123456789abcdef0123456789abcdef"} {
		resp, body = get(t, c, base+path)
		if resp.StatusCode != 200 || !strings.Contains(body, `<div id="root">`) || !strings.Contains(body, "/assets/index-") {
			t.Errorf("%s: %d, want the built index.html:\n%s", path, resp.StatusCode, body)
		}
		if resp.Header.Get("Content-Security-Policy") != wantCSP || resp.Header.Get("X-Content-Type-Options") != "nosniff" ||
			resp.Header.Get("Referrer-Policy") != "no-referrer" || resp.Header.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s headers: %v", path, resp.Header)
		}
	}
	if !strings.Contains(logs.String(), `"msg":"admin listening"`) || !strings.Contains(logs.String(), a["admin"]) {
		t.Errorf("no admin listening line:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "webhook listening") {
		t.Errorf("the webhook started without BLASTGATE_WEBHOOK_LISTEN:\n%s", logs.String())
	}
}

// The whole approver path through serve: a CLI-issued token signs in on
// the admin listener, and the policy view shows the embedded default.
func TestServeApproverSignsInAndSeesThePolicy(t *testing.T) {
	env, a := listenerEnv(t, false, nil)
	startServe(t, env)
	waitListening(t, a["admin"])
	tok := approverNewToken(t, env, "bob")
	c := caClient(t, a["data"])
	base := "https://" + a["admin"]
	b, _ := json.Marshal(map[string]string{"token": tok})
	resp, err := c.Post(base+"/api/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || len(resp.Cookies()) == 0 {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", base+"/api/policy", nil)
	req.AddCookie(resp.Cookies()[0])
	pr, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Body.Close()
	var pol struct{ Source, Text string }
	if err := json.NewDecoder(pr.Body).Decode(&pol); err != nil || pr.StatusCode != 200 {
		t.Fatalf("policy: %d %v", pr.StatusCode, err)
	}
	if pol.Source != "embedded default" || !strings.Contains(pol.Text, "default:") {
		t.Errorf("policy = %+v", pol)
	}
}

func TestServePolicyViewShowsTheFileInForce(t *testing.T) {
	text := "default: hold\nunmeasured: hold\n"
	p := writePolicy(t, text)
	env, a := listenerEnv(t, false, map[string]string{"BLASTGATE_POLICY": p})
	startServe(t, env)
	waitListening(t, a["admin"])
	tok := approverNewToken(t, env, "bob")
	c := caClient(t, a["data"])
	b, _ := json.Marshal(map[string]string{"token": tok})
	resp, err := c.Post("https://"+a["admin"]+"/api/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// Edited after start: the view must show what was loaded, not this.
	os.WriteFile(p, []byte("default: allow\n"), 0o600)
	req, _ := http.NewRequest("GET", "https://"+a["admin"]+"/api/policy", nil)
	req.AddCookie(resp.Cookies()[0])
	pr, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Body.Close()
	var pol struct{ Source, Text string }
	json.NewDecoder(pr.Body).Decode(&pol)
	if pol.Source != p || pol.Text != text {
		t.Errorf("policy = %+v, want %s with the text loaded at start", pol, p)
	}
}

// One listener that cannot bind stops serve, and the ones already bound
// are released, not left holding their ports.
func TestServeExitsWhenAListenerCannotBind(t *testing.T) {
	for _, taken := range []string{"BLASTGATE_ADMIN_LISTEN"} {
		t.Run(taken, func(t *testing.T) {
			env, _ := listenerEnv(t, false, nil)
			hold, err := net.Listen("tcp", env(taken))
			if err != nil {
				t.Fatal(err)
			}
			defer hold.Close()
			var errb syncBuf
			if code := serveCmd(refusalCtx(t), env, &errb); code != 1 || !strings.Contains(errb.String(), taken) {
				t.Fatalf("exit %d: %s", code, errb.String())
			}
			for _, k := range []string{"BLASTGATE_LISTEN", "BLASTGATE_ADMIN_LISTEN"} {
				if k == taken {
					continue
				}
				l, err := net.Listen("tcp", env(k))
				if err != nil {
					t.Errorf("%s still bound after serve exited: %v", k, err)
					continue
				}
				l.Close()
			}
		})
	}
}

func TestWarnUncovered(t *testing.T) {
	hosts := []string{"127.0.0.1", "localhost", "gate.internal"}
	for addr, warn := range map[string]bool{
		"127.0.0.1:8444":     false,
		"gate.internal:8444": false,
		"0.0.0.0:8444":       false,
		":8444":              false,
		"172.18.0.1:9443":    true,
		"other.example:8444": true,
	} {
		var b bytes.Buffer
		warnUncovered(slog.New(slog.NewJSONHandler(&b, nil)), "BLASTGATE_WEBHOOK_LISTEN", addr, hosts)
		if got := strings.Contains(b.String(), "does not cover"); got != warn {
			t.Errorf("%s: warned %v, want %v: %s", addr, got, warn, b.String())
		}
	}
}
