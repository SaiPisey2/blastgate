//go:build e2e

// Package e2e drives the real blastgate binary with the real kubectl
// against the kind fixture. Run it through `make fixture-test`.
package e2e

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	adminKC    = os.Getenv("BLASTGATE_E2E_ADMIN")
	upstreamKC = os.Getenv("BLASTGATE_E2E_UPSTREAM")
)

func TestMain(m *testing.M) {
	if adminKC == "" || upstreamKC == "" {
		fmt.Fprintln(os.Stderr, "run through: make fixture-up fixture-test")
		os.Exit(1)
	}
	out, err := exec.Command("kubectl", "--kubeconfig", adminKC, "config", "current-context").Output()
	if ctx := strings.TrimSpace(string(out)); err != nil || ctx != "kind-blastgate-fixture" {
		fmt.Fprintf(os.Stderr, "refusing: admin kubeconfig context is %q, not kind-blastgate-fixture\n", ctx)
		os.Exit(1)
	}
	// blastgate forwards with the upstream kubeconfig, so that is the file
	// that decides which cluster the tests touch. It must point at the
	// same API server as the fixture's admin kubeconfig.
	adminServer, upServer := server(adminKC), server(upstreamKC)
	if adminServer == "" || upServer == "" || adminServer != upServer {
		fmt.Fprintf(os.Stderr, "refusing: upstream kubeconfig server %q is not the fixture's server %q\n", upServer, adminServer)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func server(kubeconfig string) string {
	out, err := exec.Command("kubectl", "--kubeconfig", kubeconfig, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

type logBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type gate struct {
	env  []string
	logs *logBuf
	api  *adminClient // signed in as bob on first use; see (*gate).admin
}

// freeAddr returns host:port for a port nothing is listening on right
// now. Every listener blastgate opens gets one (ruling P2-R26): the
// defaults (8443, 8444) may be taken on the machine running the suite,
// or by a blastgate a previous test has not finished stopping.
func freeAddr(t *testing.T, host string) string {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// value is the last setting of key in the gate's environment, the one
// blastgate reads.
func (g *gate) value(key string) string {
	v := ""
	for _, kv := range g.env {
		if s, ok := strings.CutPrefix(kv, key+"="); ok {
			v = s
		}
	}
	return v
}

// start runs blastgate serve with a 3s hold, so a held request's ticket
// comes back quickly; extra env entries (for example a longer
// BLASTGATE_HOLD) override the defaults, since exec keeps the last of
// duplicate keys.
func start(t *testing.T, extra ...string) *gate {
	t.Helper()
	addr := freeAddr(t, "127.0.0.1")
	key := make([]byte, 32)
	rand.Read(key)
	dir := t.TempDir()
	g := &gate{logs: &logBuf{}, env: []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"BLASTGATE_DATA_DIR=" + filepath.Join(dir, "data"),
		"BLASTGATE_LISTEN=" + addr,
		"BLASTGATE_ADMIN_LISTEN=" + freeAddr(t, "127.0.0.1"),
		"BLASTGATE_UPSTREAM_KUBECONFIG=" + upstreamKC,
		"BLASTGATE_SIGNING_KEY=" + hex.EncodeToString(key),
		"BLASTGATE_HOLD=3s",
	}}
	g.env = append(g.env, extra...)
	cmd := exec.Command("../blastgate", "serve")
	cmd.Env, cmd.Stderr = g.env, g.logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Signal(os.Interrupt)
		cmd.Wait()
		if t.Failed() {
			t.Logf("blastgate log:\n%s", g.logs.String())
		}
	})
	// serve binds every listener before serving any, so once the proxy
	// and the admin listener answer, the webhook's port is bound too.
	for _, a := range []string{addr, g.value("BLASTGATE_ADMIN_LISTEN")} {
		listening := false
		for i := 0; i < 100 && !listening; i++ {
			if c, err := tls.Dial("tcp", a, &tls.Config{InsecureSkipVerify: true}); err == nil {
				c.Close()
				listening = true
			} else {
				time.Sleep(100 * time.Millisecond)
			}
		}
		if !listening {
			t.Fatalf("blastgate never listened on %s:\n%s", a, g.logs.String())
		}
	}
	return g
}

// adminClient talks to the admin listener the way the UI does: over TLS
// verified against blastgate's own CA, carrying the session cookie in a
// jar and the CSRF value on every call that is not a GET.
type adminClient struct {
	c    *http.Client
	base string
	csrf string
}

// adminHTTP is a client for the admin listener that trusts only
// blastgate's CA. http2 picks the protocol: the stream must work over
// both, since a browser may speak either. No proxy from the environment:
// the listener is on loopback, and an HTTPS_PROXY must not see the cookie.
func (g *gate) adminHTTP(t *testing.T, http2 bool, jar http.CookieJar) *http.Client {
	t.Helper()
	ca, err := os.ReadFile(filepath.Join(g.value("BLASTGATE_DATA_DIR"), "tls", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("blastgate's ca.crt holds no certificate")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	tr.ForceAttemptHTTP2 = http2
	if !http2 {
		// A non-nil empty map is how net/http is told never to upgrade.
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}
	return &http.Client{Transport: tr, Jar: jar, Timeout: 30 * time.Second}
}

// admin returns a client signed in as bob, an approver created with
// `blastgate approver new` exactly as an operator would, logged in
// through POST /api/login with the token it printed.
func (g *gate) admin(t *testing.T) *adminClient {
	t.Helper()
	if g.api != nil {
		return g.api
	}
	tok, err := g.run(t, "approver", "new", "--name", "bob")
	if err != nil {
		t.Fatalf("approver new: %v", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	a := &adminClient{c: g.adminHTTP(t, true, jar), base: "https://" + g.value("BLASTGATE_ADMIN_LISTEN")}
	body, _ := json.Marshal(map[string]string{"token": strings.TrimSpace(tok)})
	res, err := a.c.Post(a.base+"/api/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var me struct{ Name, CSRF string }
	if err := json.NewDecoder(res.Body).Decode(&me); err != nil || res.StatusCode != http.StatusOK || me.Name != "bob" || me.CSRF == "" {
		t.Fatalf("login: status %d, name %q, err %v", res.StatusCode, me.Name, err)
	}
	a.csrf = me.CSRF
	g.api = a
	return a
}

// do sends one API call and decodes a JSON answer into out (when non-nil),
// returning the status. Non-GET calls carry the CSRF header, as the UI's.
func (a *adminClient) do(t *testing.T, method, path string, body, out any) int {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, a.base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("X-Blastgate-CSRF", a.csrf)
	}
	res, err := a.c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if out != nil && res.StatusCode < 300 {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s %s: %v:\n%s", method, path, err, b)
		}
	}
	if res.StatusCode >= 300 {
		t.Logf("%s %s: %d %s", method, path, res.StatusCode, b)
	}
	return res.StatusCode
}

// startWithWebhook runs blastgate with its observe webhook listening
// where the kind API server can reach it, registers the webhook in the
// cluster with `blastgate webhook-config` and the fixture's admin
// kubeconfig, and removes the registration when the test ends.
//
// The address is the kind network's gateway (BLASTGATE_E2E_HOST_IP), the
// host's side of the bridge the node sits on. With Docker Desktop the
// bridge lives inside Docker's VM, so no host interface has that address
// and the bind fails; there the host's own outbound address is used
// instead, which the node reaches through the VM's NAT. Either way the
// node is asked to reach the listener before anything is registered: a
// registration it cannot reach would, under failurePolicy Ignore, record
// nothing, and every webhook assertion would be about an empty table.
func startWithWebhook(t *testing.T) *gate {
	t.Helper()
	host := webhookHost(t)
	addr := freeAddr(t, host)
	g := start(t, "BLASTGATE_WEBHOOK_LISTEN="+addr, "BLASTGATE_ALLOW_REMOTE=1", "BLASTGATE_TLS_HOSTS=127.0.0.1,localhost,"+host)
	// GET on /validate is a 405: reached, TLS done, the handler answering.
	probe, _ := exec.Command("docker", "exec", fixtureNode, "curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
		"--max-time", "5", "https://"+addr+"/validate").Output()
	if code := strings.TrimSpace(string(probe)); code != "405" && code != "400" {
		t.Logf("probe of https://%s/validate from %s answered %q", addr, fixtureNode, code)
		t.Skip("host not reachable from kind")
	}
	cfg, err := g.run(t, "webhook-config", "--url", "https://"+addr+"/validate")
	if err != nil {
		t.Fatalf("webhook-config: %v", err)
	}
	t.Cleanup(func() {
		kubectl(t, adminKC, nil, "", "delete", "validatingwebhookconfiguration", "blastgate-observe", "--ignore-not-found")
	})
	must(t)(kubectl(t, adminKC, nil, cfg, "apply", "-f", "-"))
	// The API server picks up a new registration a moment after it is
	// created. Until a write is seen, the webhook tests would pass for
	// the wrong reason (no bypass row because nothing was observed).
	g.bypassBarrier(t)
	return g
}

// fixtureNode is the kind node container of the blastgate-fixture cluster.
const fixtureNode = "blastgate-fixture-control-plane"

func webhookHost(t *testing.T) string {
	t.Helper()
	gw := os.Getenv("BLASTGATE_E2E_HOST_IP")
	if net.ParseIP(gw) == nil {
		t.Fatalf("BLASTGATE_E2E_HOST_IP %q is not an address; run through make fixture-test", gw)
	}
	if l, err := net.Listen("tcp", net.JoinHostPort(gw, "0")); err == nil {
		l.Close()
		return gw
	}
	// A UDP "connection" sends nothing; it only asks the routing table
	// which local address traffic toward the gateway would leave from.
	c, err := net.Dial("udp", net.JoinHostPort(gw, "9"))
	if err != nil {
		t.Skip("host not reachable from kind")
	}
	defer c.Close()
	host := c.LocalAddr().(*net.UDPAddr).IP.String()
	t.Logf("kind gateway %s is not a local address (Docker Desktop); webhook listens on %s", gw, host)
	return host
}

// bypassRow is one row of GET /api/bypass.
type bypassRow struct {
	At          string   `json:"at"`
	User        string   `json:"user"`
	Groups      []string `json:"groups"`
	Verb        string   `json:"verb"`
	Resource    string   `json:"resource"`
	Subresource string   `json:"subresource"`
	Namespace   string   `json:"namespace"`
	Name        string   `json:"name"`
	DryRun      bool     `json:"dry_run"`
}

func (g *gate) bypasses(t *testing.T) []bypassRow {
	t.Helper()
	var rows []bypassRow
	if code := g.admin(t).do(t, http.MethodGet, "/api/bypass?since_hours=1&limit=500", nil, &rows); code != http.StatusOK {
		t.Fatalf("GET /api/bypass: %d", code)
	}
	return rows
}

// bypassBarrier makes a write around blastgate -- a server-side dry run,
// which reaches webhooks declaring sideEffects None and changes nothing --
// and waits for its row. The webhook runs inside the API server's
// handling of each write, so once this row is in, every write that
// returned before the barrier began has been observed or ignored for
// good: an absent row afterwards is a real absence, not a slow one.
func (g *gate) bypassBarrier(t *testing.T) []bypassRow {
	t.Helper()
	name := fmt.Sprintf("e2e-barrier-%d", time.Now().UnixNano())
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		must(t)(kubectl(t, adminKC, nil, "", "create", "configmap", name, "-n", "demo", "--dry-run=server"))
		rows := g.bypasses(t)
		for _, r := range rows {
			if r.Name == name {
				return rows
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("the webhook never observed a write made around blastgate\n%s", g.logs.String())
	return nil
}

func (g *gate) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("../blastgate", args...)
	cmd.Env = g.env
	out, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), fmt.Errorf("%v: %s", err, ee.Stderr)
	}
	return string(out), err
}

func (g *gate) session(t *testing.T, human string) string {
	t.Helper()
	out, err := g.run(t, "session", "new", "--human", human, "--agent", "e2e", "--ttl", "1h", "--namespace", "demo")
	if err != nil {
		t.Fatalf("session new: %v", err)
	}
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(p, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// kubectl runs with only the given kubeconfig and a throwaway HOME, so no
// discovery cache or default kubeconfig from this machine is involved.
func kubectl(t *testing.T, kc string, env []string, stdin string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", kc}, args...)...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}, env...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// must fails the test when a kubectl call fails. It returns a function so
// that kubectl's two results can be passed straight in: Go allows f(g())
// only when g's results are f's only arguments.
func must(t *testing.T) func(string, error) string {
	return func(out string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatalf("%v:\n%s", err, out)
		}
		return out
	}
}

// writeTemp writes content to a private file in the test's temp dir.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "file.yaml")
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

var approvalID = regexp.MustCompile(`[0-9a-f]{32}`)

// approveWhileHeld approves every pending approval as it appears, until
// the returned function is called. Under the default policy every exec,
// attach and port-forward is unmeasured and so held; the compatibility
// tests are about the streams working through blastgate once released,
// so a person approving inline stands in for the one who would.
//
// It fails the test if two approvals are ever pending at once: the tests
// run one command at a time, so a second pending approval is a twin --
// kubectl's WebSocket attempt and its SPDY fallback digesting differently
// (final review I1) -- which approving everything would otherwise hide.
func (g *gate) approveWhileHeld(t *testing.T) (stop func()) {
	t.Helper()
	done, finished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		seen := map[string]bool{}
		for {
			select {
			case <-done:
				return
			case <-time.After(200 * time.Millisecond):
			}
			list, _ := g.run(t, "approvals", "--status", "pending")
			ids := approvalID.FindAllString(list, -1)
			if len(ids) > 1 {
				t.Errorf("%d approvals pending at once for one command:\n%s", len(ids), list)
			}
			for _, id := range ids {
				if !seen[id] {
					seen[id] = true
					g.run(t, "approve", id, "--by", "bob")
				}
			}
		}
	}()
	return func() { close(done); <-finished }
}

// With read access (for scoring) the service account could read the demo
// namespace by itself; what must stay true is that it cannot write there,
// so every write that lands does so as the impersonated human.
func TestTheServiceAccountAloneCannotWrite(t *testing.T) {
	pod := strings.TrimPrefix(strings.TrimSpace(must(t)(kubectl(t, adminKC, nil, "", "get", "pods", "-n", "demo", "-l", "app=web", "-o", "name"))), "pod/")
	for _, args := range [][]string{
		{"delete", "pod", pod, "-n", "demo", "--dry-run=server"},
		{"create", "configmap", "e2e-sa-write", "-n", "demo", "--dry-run=server"},
	} {
		out, err := kubectl(t, upstreamKC, nil, "", args...)
		if err == nil || !strings.Contains(out, "forbidden") {
			t.Errorf("the service account can %s by itself, so the other tests prove nothing:\n%s", args[0], out)
		}
	}
}

func TestGetThroughTheProxy(t *testing.T) {
	g := start(t)
	out := must(t)(kubectl(t, g.session(t, "alice"), nil, "", "get", "pods", "-n", "demo"))
	if !strings.Contains(out, "web-") {
		t.Errorf("no web pod listed:\n%s", out)
	}
}

func TestForwardedAsTheHumanWithAgentAndSession(t *testing.T) {
	g := start(t)
	out := must(t)(kubectl(t, g.session(t, "alice"), nil, "", "auth", "whoami", "-o", "json"))
	var r struct {
		Status struct {
			UserInfo struct {
				Username string              `json:"username"`
				Extra    map[string][]string `json:"extra"`
			} `json:"userInfo"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	u := r.Status.UserInfo
	if u.Username != "alice" {
		t.Errorf("username = %q, want alice", u.Username)
	}
	if len(u.Extra["blastgate-agent"]) != 1 || u.Extra["blastgate-agent"][0] != "e2e" {
		t.Errorf("agent extra = %v", u.Extra)
	}
	if len(u.Extra["blastgate-session"]) != 1 || u.Extra["blastgate-session"][0] == "" {
		t.Errorf("session extra = %v", u.Extra)
	}
}

func TestTheHumansOwnPermissionsApply(t *testing.T) {
	g := start(t)
	out, err := kubectl(t, g.session(t, "alice"), nil, "", "get", "pods", "-n", "other")
	if err == nil || !strings.Contains(out, `User "alice"`) {
		t.Errorf("alice read a namespace she has no role in, or the error does not name her:\n%s", out)
	}
}

func TestClientImpersonationIsRefused(t *testing.T) {
	g := start(t)
	out, err := kubectl(t, g.session(t, "alice"), nil, "", "--as=system:admin", "get", "pods", "-n", "demo")
	if err == nil || !strings.Contains(out, "impersonation") {
		t.Errorf("--as was not refused:\n%s", out)
	}
}

// kubectl never prints the body of a 401 on discovery, its first request;
// it prints a fixed "provide credentials" line, as it does for the API
// server's own 401s. "Unauthorized" reaches the output only through the
// Warning header blastgate adds to every Status it writes.
func TestRevokedSessionIsRejected(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	must(t)(kubectl(t, kc, nil, "", "get", "pods", "-n", "demo"))
	list, err := g.run(t, "session", "list")
	if err != nil {
		t.Fatalf("session list: %v", err)
	}
	rows := strings.Split(strings.TrimSpace(list), "\n")
	if len(rows) != 2 {
		t.Fatalf("session list: want a header and one session:\n%s", list)
	}
	id := strings.Fields(rows[1])[0]
	if _, err := g.run(t, "session", "revoke", id); err != nil {
		t.Fatal(err)
	}
	out, err := kubectl(t, kc, nil, "", "get", "pods", "-n", "demo")
	if err == nil || !strings.Contains(out, "Unauthorized") {
		t.Errorf("a revoked session still works:\n%s", out)
	}
}

func TestWatchStreamsEvents(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kc, "get", "pods", "-n", "demo", "-l", "app=web", "--watch", "--output-watch-events")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	lines := make(chan string, 16)
	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			lines <- s.Text()
		}
		close(lines)
	}()
	waitFor := func(word string) {
		t.Helper()
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("watch ended before %s", word)
				}
				if strings.Contains(l, word) {
					return
				}
			case <-ctx.Done():
				t.Fatalf("no %s event within the deadline", word)
			}
		}
	}
	waitFor("ADDED")
	must(t)(kubectl(t, kc, nil, "", "annotate", "pods", "-n", "demo", "-l", "app=web", fmt.Sprintf("e2e-tick=%d", time.Now().UnixNano()), "--overwrite"))
	waitFor("MODIFIED")
}

func TestExecOverWebSocketAndSPDY(t *testing.T) {
	g := start(t, "BLASTGATE_HOLD=10s")
	kc := g.session(t, "alice")
	defer g.approveWhileHeld(t)()
	for _, ws := range []string{"true", "false"} {
		env := []string{"KUBECTL_REMOTE_COMMAND_WEBSOCKETS=" + ws}
		out := must(t)(kubectl(t, kc, env, "", "exec", "-n", "demo", "deploy/web", "--", "echo", "hello-"+ws))
		if !strings.Contains(out, "hello-"+ws) {
			t.Errorf("websockets=%s: %q", ws, out)
		}
		out = must(t)(kubectl(t, kc, env, "piped-through-"+ws, "exec", "-i", "-n", "demo", "deploy/web", "--", "cat"))
		if !strings.Contains(out, "piped-through-"+ws) {
			t.Errorf("stdin, websockets=%s: %q", ws, out)
		}
	}
}

func TestPortForward(t *testing.T) {
	g := start(t, "BLASTGATE_HOLD=10s")
	kc := g.session(t, "alice")
	defer g.approveWhileHeld(t)()
	for _, ws := range []string{"true", "false"} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kc, "port-forward", "-n", "demo", "deploy/web", ":8080")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "KUBECTL_PORT_FORWARD_WEBSOCKETS=" + ws}
		stdout, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		m := regexp.MustCompile(`127\.0\.0\.1:(\d+)`).FindStringSubmatch(line)
		if m == nil {
			cmd.Process.Kill()
			cancel()
			t.Fatalf("websockets=%s: no forwarding line: %q", ws, line)
		}
		res, err := http.Get("http://127.0.0.1:" + m[1] + "/")
		if err != nil {
			t.Errorf("websockets=%s: %v", ws, err)
		} else {
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if !strings.Contains(string(b), "blastgate-ok") {
				t.Errorf("websockets=%s: body %q", ws, b)
			}
		}
		cmd.Process.Kill()
		cmd.Wait()
		cancel()
	}
}

func TestLogsAndFollow(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	out := must(t)(kubectl(t, kc, nil, "", "logs", "-n", "demo", "deploy/web"))
	if !strings.Contains(out, "started") {
		t.Errorf("logs: %q", out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kc, "logs", "-f", "-n", "demo", "deploy/web")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	first, _ := bufio.NewReader(stdout).ReadString('\n')
	if !strings.Contains(first, "started") {
		t.Errorf("logs -f first line %q", first)
	}
}

func TestServerSideApplyAndDelete(t *testing.T) {
	g := start(t)
	kc := g.session(t, "alice")
	f := writeTemp(t, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: e2e-apply\n  namespace: demo\ndata:\n  k: v\n")
	out := must(t)(kubectl(t, kc, nil, "", "apply", "--server-side", "-f", f))
	if !strings.Contains(out, "serverside-applied") {
		t.Errorf("apply: %q", out)
	}
	// Deleting a ConfigMap is COMPENSABLE (it can be recreated from the
	// snapshot, but whatever read it notices), and the default policy
	// holds what it does not name as safe: held, approved, retried.
	out, err := kubectl(t, kc, nil, "", "delete", "configmap", "e2e-apply", "-n", "demo")
	m := ticket.FindStringSubmatch(out)
	if err == nil || m == nil {
		t.Fatalf("configmap delete was not held with a ticket:\n%s", out)
	}
	if _, err := g.run(t, "approve", m[1], "--by", "bob"); err != nil {
		t.Fatal(err)
	}
	must(t)(kubectl(t, kc, nil, "", "delete", "configmap", "e2e-apply", "-n", "demo"))
}

func percentiles(d []time.Duration) (p50, p95 time.Duration) {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[len(d)/2], d[len(d)*95/100]
}

func timeLists(t *testing.T, kc string) []time.Duration {
	t.Helper()
	cfg, err := clientcmd.BuildConfigFromFlags("", kc)
	if err != nil {
		t.Fatal(err)
	}
	// Otherwise client-go's default client-side rate limiter (QPS 5, burst
	// 10) throttles both legs to one request per 200ms after warm-up, and
	// the test measures the throttle instead of the network.
	cfg.QPS = -1
	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 10; i++ { // warm connections and caches
		if _, err := c.CoreV1().Pods("demo").List(ctx, metav1.ListOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	out := make([]time.Duration, 0, 200)
	for i := 0; i < 200; i++ {
		s := time.Now()
		if _, err := c.CoreV1().Pods("demo").List(ctx, metav1.ListOptions{}); err != nil {
			t.Fatal(err)
		}
		out = append(out, time.Since(s))
	}
	return out
}

// Reads must add close to nothing (design §9). Printed on every run so the
// number is visible; the bound only catches something pathological, since
// shared CI runners are too noisy for a tight one.
func TestAddedLatencyOnReads(t *testing.T) {
	g := start(t)
	d50, d95 := percentiles(timeLists(t, adminKC))
	p50, p95 := percentiles(timeLists(t, g.session(t, "alice")))
	t.Logf("direct p50 %v p95 %v | via blastgate p50 %v p95 %v | added p50 %v p95 %v", d50, d95, p50, p95, p50-d50, p95-d95)
	if p95-d95 > 50*time.Millisecond {
		t.Errorf("blastgate adds %v at p95", p95-d95)
	}
}
