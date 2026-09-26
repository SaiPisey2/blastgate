package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/SaiPisey2/blastgate/internal/config"
	"github.com/SaiPisey2/blastgate/internal/store"
	"github.com/SaiPisey2/blastgate/internal/tlsutil"
	"github.com/SaiPisey2/blastgate/internal/webhook"
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

func review(user, uid string) string {
	return `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"` + uid +
		`","kind":{"group":"","version":"v1","kind":"ConfigMap"},"resource":{"group":"","version":"v1","resource":"configmaps"},` +
		`"name":"settings","namespace":"demo","operation":"CREATE","userInfo":{"username":"` + user + `"}}}`
}

func postReview(t *testing.T, c *http.Client, addr, body string) (string, error) {
	t.Helper()
	resp, err := c.Post("https://"+addr+"/validate", "application/json", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func bypassUsers(t *testing.T, dataDir string) []string {
	t.Helper()
	st, err := store.Open(filepath.Join(dataDir, "blastgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows, err := st.BypassSince(context.Background(), time.Now().Add(-time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	var users []string
	for _, r := range rows {
		users = append(users, r.User)
	}
	slices.Sort(users)
	return users
}

func TestServeStartsTheWebhook(t *testing.T) {
	env, a := listenerEnv(t, true, map[string]string{"BLASTGATE_BYPASS_IGNORE": "system:node:,ops-bot"})
	logs := startServe(t, env)
	waitListening(t, a["webhook"])
	c := caClient(t, a["data"])
	for _, u := range []string{"mallory", "ops-bot", "system:node:kind-worker", "system:kube-scheduler"} {
		body, err := postReview(t, c, a["webhook"], review(u, "uid-"+u))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body, `"allowed":true`) || !strings.Contains(body, "uid-"+u) {
			t.Errorf("%s: %s", u, body)
		}
	}
	// BLASTGATE_BYPASS_IGNORE replaced the default list: the scheduler is
	// no longer ignored, ops-bot is.
	if got := bypassUsers(t, a["data"]); !slices.Equal(got, []string{"mallory", "system:kube-scheduler"}) {
		t.Errorf("bypass rows for %v, want mallory and system:kube-scheduler", got)
	}
	if !strings.Contains(logs.String(), `"msg":"webhook listening"`) || !strings.Contains(logs.String(), `"client_cert":false`) {
		t.Errorf("no webhook listening line:\n%s", logs.String())
	}
}

// leaseReview is a controller's Lease renewal, the webhook's usual noise.
func leaseReview(user, uid string) string {
	return `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"` + uid +
		`","kind":{"group":"coordination.k8s.io","version":"v1","kind":"Lease"},"resource":{"group":"coordination.k8s.io","version":"v1","resource":"leases"},` +
		`"name":"cert-manager-controller","namespace":"cert-manager","operation":"UPDATE","userInfo":{"username":"` + user + `"}}}`
}

// TestServeSkipsLeaseNoiseUnlessAsked: serve hands the webhook the
// setting; without it a Lease renewal is not recorded, with it it is.
func TestServeSkipsLeaseNoiseUnlessAsked(t *testing.T) {
	for _, include := range []string{"", "1"} {
		env, a := listenerEnv(t, true, map[string]string{"BLASTGATE_BYPASS_INCLUDE_NOISE": include})
		startServe(t, env)
		waitListening(t, a["webhook"])
		c := caClient(t, a["data"])
		for _, body := range []string{leaseReview("lease-holder", "uid-lease"), review("mallory", "uid-cm")} {
			if out, err := postReview(t, c, a["webhook"], body); err != nil || !strings.Contains(out, `"allowed":true`) {
				t.Fatalf("include=%q: %s %v", include, out, err)
			}
		}
		want := []string{"mallory"}
		if include == "1" {
			want = []string{"lease-holder", "mallory"}
		}
		if got := bypassUsers(t, a["data"]); !slices.Equal(got, want) {
			t.Errorf("include=%q: bypass rows for %v, want %v", include, got, want)
		}
	}
}

// clientPKI writes a CA to a PEM file and returns it with a client
// certificate that CA signed.
func clientPKI(t *testing.T) (caPath string, client tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "apiserver-client-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "kube-apiserver"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath = filepath.Join(t.TempDir(), "client-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return caPath, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestServeWebhookRequiresAClientCertWhenTheCAIsSet(t *testing.T) {
	caPath, cert := clientPKI(t)
	env, a := listenerEnv(t, true, map[string]string{"BLASTGATE_WEBHOOK_CLIENT_CA": caPath})
	logs := startServe(t, env)
	waitListening(t, a["webhook"])

	if _, err := postReview(t, caClient(t, a["data"]), a["webhook"], review("mallory", "uid-anon")); err == nil {
		t.Error("a client with no certificate reached the webhook")
	}
	_, otherCert := clientPKI(t)
	if _, err := postReview(t, caClient(t, a["data"], otherCert), a["webhook"], review("mallory", "uid-other")); err == nil {
		t.Error("a certificate from another CA reached the webhook")
	}
	body, err := postReview(t, caClient(t, a["data"], cert), a["webhook"], review("mallory", "uid-ok"))
	if err != nil || !strings.Contains(body, `"allowed":true`) {
		t.Fatalf("the API server's certificate was refused: %v %s", err, body)
	}
	if got := bypassUsers(t, a["data"]); !slices.Equal(got, []string{"mallory"}) {
		t.Errorf("bypass rows for %v, want the one authenticated review", got)
	}
	if !strings.Contains(logs.String(), `"client_cert":true`) {
		t.Errorf("the log does not say a client certificate is required:\n%s", logs.String())
	}
}

func TestServeRefusesABadWebhookClientCA(t *testing.T) {
	notPEM := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(notPEM, []byte("not a certificate"), 0o600)
	for name, path := range map[string]string{"missing": filepath.Join(t.TempDir(), "nope.pem"), "not pem": notPEM} {
		t.Run(name, func(t *testing.T) {
			env, _ := listenerEnv(t, true, map[string]string{"BLASTGATE_WEBHOOK_CLIENT_CA": path})
			var errb syncBuf
			if code := serveCmd(refusalCtx(t), env, &errb); code != 2 || !strings.Contains(errb.String(), "BLASTGATE_WEBHOOK_CLIENT_CA") {
				t.Errorf("exit %d: %s", code, errb.String())
			}
		})
	}
}

// One listener that cannot bind stops serve, and the ones already bound
// are released, not left holding their ports.
func TestServeExitsWhenAListenerCannotBind(t *testing.T) {
	for _, taken := range []string{"BLASTGATE_ADMIN_LISTEN", "BLASTGATE_WEBHOOK_LISTEN"} {
		t.Run(taken, func(t *testing.T) {
			env, _ := listenerEnv(t, true, nil)
			hold, err := net.Listen("tcp", env(taken))
			if err != nil {
				t.Fatal(err)
			}
			defer hold.Close()
			var errb syncBuf
			if code := serveCmd(refusalCtx(t), env, &errb); code != 1 || !strings.Contains(errb.String(), taken) {
				t.Fatalf("exit %d: %s", code, errb.String())
			}
			for _, k := range []string{"BLASTGATE_LISTEN", "BLASTGATE_ADMIN_LISTEN", "BLASTGATE_WEBHOOK_LISTEN"} {
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

// A nil *store.Store boxed into webhook.Recorder is not == nil; the
// handler's own nil check would pass it and AppendBypass would panic.
func TestBypassRecorderNeverBoxesANilStore(t *testing.T) {
	if r := bypassRecorder(nil); r != nil {
		t.Errorf("bypassRecorder(nil) = %#v, want a nil interface", r)
	}
	h := &webhook.Handler{Rec: bypassRecorder(nil)}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/validate", strings.NewReader(review("mallory", "uid-nil"))))
	if !strings.Contains(rec.Body.String(), `"allowed":true`) {
		t.Errorf("a webhook with no store did not allow the review: %d %s", rec.Code, rec.Body.String())
	}
}

// config cannot import the webhook package; this keeps its copy of the
// default ignore list from drifting.
func TestBypassIgnoreDefaultIsTheWebhooks(t *testing.T) {
	c, err := config.Load(serveEnv(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.BypassIgnore, webhook.DefaultIgnore) {
		t.Errorf("config default %v, webhook.DefaultIgnore %v", c.BypassIgnore, webhook.DefaultIgnore)
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

// An open /api/stream must not hold shutdown for its whole budget: the
// stream is cancelled when shutdown begins, over either protocol a
// browser may use.
func TestServeShutdownEndsOpenStreams(t *testing.T) {
	for _, h2 := range []bool{true, false} {
		name := "http1.1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			env, a := listenerEnv(t, false, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan int, 1)
			logs := &syncBuf{}
			go func() { done <- serveCmd(ctx, env, logs) }()
			waitListening(t, a["admin"])
			tok := approverNewToken(t, env, "bob")
			c := caClient(t, a["data"])
			tr := c.Transport.(*http.Transport)
			tr.ForceAttemptHTTP2 = h2
			// One connection: the stream must reuse the login's. With two
			// allowed, a stream sent before the login connection is back in
			// the pool starts a second dial that then sits in the pool
			// unused, and Shutdown waits 5s on a connection that never sent
			// a request (net/http's StateNew rule), not on the stream.
			tr.MaxConnsPerHost = 1
			c.Timeout = 0
			b, _ := json.Marshal(map[string]string{"token": tok})
			resp, err := c.Post("https://"+a["admin"]+"/api/login", "application/json", bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			req, _ := http.NewRequest("GET", "https://"+a["admin"]+"/api/stream", nil)
			req.AddCookie(resp.Cookies()[0])
			sr, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer sr.Body.Close()
			if want := map[bool]int{true: 2, false: 1}[h2]; sr.StatusCode != 200 || sr.ProtoMajor != want {
				t.Fatalf("stream %d over HTTP/%d, want 200 over HTTP/%d", sr.StatusCode, sr.ProtoMajor, want)
			}
			// id: 0, then event: hello.
			br := bufio.NewReader(sr.Body)
			var head string
			for i := 0; i < 2; i++ {
				line, err := br.ReadString('\n')
				if err != nil {
					t.Fatal(err)
				}
				head += line
			}
			if !strings.Contains(head, "event: hello") {
				t.Fatalf("stream began %q, want hello", head)
			}

			began := time.Now()
			cancel()
			select {
			case code := <-done:
				if took := time.Since(began); took > 2*time.Second {
					t.Errorf("shutdown took %v with a stream open; the budget is 5s and a stream must not use it", took)
				}
				if code != 0 {
					t.Errorf("exit %d", code)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("serve did not shut down")
			}
			if strings.Contains(logs.String(), `"msg":"shutdown"`) {
				t.Errorf("shutdown warned:\n%s", logs.String())
			}
		})
	}
}
