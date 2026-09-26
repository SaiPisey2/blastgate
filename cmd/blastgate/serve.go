package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"k8s.io/client-go/rest"

	"github.com/SaiPisey2/sounding/pkg/cluster"
	"github.com/SaiPisey2/sounding/pkg/model"
	"github.com/SaiPisey2/sounding/pkg/score"

	"github.com/SaiPisey2/blastgate/internal/admin"
	"github.com/SaiPisey2/blastgate/internal/approval"
	"github.com/SaiPisey2/blastgate/internal/config"
	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/gate"
	"github.com/SaiPisey2/blastgate/internal/policy"
	"github.com/SaiPisey2/blastgate/internal/proxy"
	"github.com/SaiPisey2/blastgate/internal/session"
	"github.com/SaiPisey2/blastgate/internal/snapshot"
	"github.com/SaiPisey2/blastgate/internal/store"
	"github.com/SaiPisey2/blastgate/internal/tlsutil"
	"github.com/SaiPisey2/blastgate/internal/upstream"
	"github.com/SaiPisey2/blastgate/internal/webhook"
	"github.com/SaiPisey2/blastgate/ui"
)

// serveCmd wires config, store, TLS, upstream and proxy into a running
// HTTPS server, beside the admin listener (the approver UI) and, when
// configured, the observe webhook, and shuts them all down cleanly when
// ctx is cancelled. Logging is JSON: the proxy logs attacker-chosen
// header names, and JSON escaping keeps those safe in the log stream.
func serveCmd(ctx context.Context, getenv func(string) string, stderr io.Writer) int {
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	cfg, err := config.Load(getenv)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// The policy is read before anything is opened or listened on: a
	// policy an operator got wrong must stop the start, not surface as
	// every write held for a reason nobody can see.
	pol, policyName := policy.Default(), "default"
	policySource, policyText := "embedded default", policy.DefaultText()
	if cfg.PolicyPath != "" {
		if pol, policyText, err = readPolicy(cfg.PolicyPath); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		policyName, policySource = cfg.PolicyPath, cfg.PolicyPath
	}
	// Read before anything listens, for the same reason as the policy: a
	// CA file that is missing or holds no certificate must stop the start,
	// not leave a webhook that refuses every API server call and, under
	// failurePolicy Ignore, silently records nothing.
	var webhookCAs *x509.CertPool
	if cfg.WebhookClientCA != "" {
		if webhookCAs, err = loadClientCAs(cfg.WebhookClientCA); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	st, err := openStore(cfg.DataDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer st.Close()
	cert, _, err := tlsutil.LoadOrCreate(filepath.Join(cfg.DataDir, "tls"), cfg.TLSHosts)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	up, err := upstream.Load(cfg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	auth := &session.Authenticator{Store: st, Now: time.Now}
	eng := engine.New(up, cfg.ScoreBudget)
	svc := &approval.Service{Store: st, Key: cfg.SigningKey, TokenTTL: cfg.ApprovalTTL, PendingTTL: pendingTTL, Now: time.Now}
	g := &gate.Gate{
		Engine:    eng,
		Policy:    pol,
		Approvals: approvalsAdapter{svc: svc, st: st},
		Audit:     st,
		Snapshots: &snapshot.Taker{
			Dir:           filepath.Join(cfg.DataDir, "snapshots"),
			Engine:        eng,
			SoundingScore: soundingSnapshot(up.Config),
		},
		// The snapshot re-reads what scoring read; the same budget bounds it.
		SnapshotBudget: cfg.ScoreBudget,
		Hold:           cfg.Hold,
		Poll:           500 * time.Millisecond,
		Log:            log,
	}
	tlsConfig := func() *tls.Config {
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	errorLog := slog.NewLogLogger(log.Handler(), slog.LevelWarn)
	proxySrv := &http.Server{
		Handler:           proxy.New(auth, g, up, log),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: watches, logs -f and exec sessions are meant
		// to outlive any fixed deadline.
		//
		// IdleTimeout closes only a keep-alive connection waiting for its
		// next request: a streaming response is not idle, and a hijacked
		// exec or port-forward is no longer the server's. Without it an
		// idle client holds its connection and goroutine forever.
		IdleTimeout: 120 * time.Second,
		TLSConfig:   tlsConfig(),
		ErrorLog:    errorLog,
	}
	adminSrv := &http.Server{
		Handler: admin.NewServer(admin.NewAuth(st, log), admin.Deps{
			Store: st, Approvals: svc, Policy: pol, PolicySource: policySource, PolicyText: policyText, Log: log,
		}, ui.FS()),
		ReadHeaderTimeout: adminReadHeaderTimeout,
		ReadTimeout:       adminReadTimeout,
		// /api/stream outlives this: it sets its own deadline before each
		// write, which replaces the server's, and clears it after.
		WriteTimeout: adminWriteTimeout,
		IdleTimeout:  adminIdleTimeout,
		TLSConfig:    tlsConfig(),
		ErrorLog:     errorLog,
	}
	// Every admin request's context descends from adminCtx, cancelled the
	// moment Shutdown begins. An open /api/stream never goes idle, so
	// Shutdown would otherwise wait out its whole 5s for each browser tab
	// and then warn; cancelled, the streams end at once and the browsers
	// reconnect to whatever serve comes next.
	adminCtx, cancelAdmin := context.WithCancel(context.Background())
	defer cancelAdmin()
	adminSrv.BaseContext = func(net.Listener) context.Context { return adminCtx }
	adminSrv.RegisterOnShutdown(cancelAdmin)
	servers := []*listener{
		{setting: "BLASTGATE_LISTEN", addr: cfg.Listen, srv: proxySrv},
		{setting: "BLASTGATE_ADMIN_LISTEN", addr: cfg.AdminListen, srv: adminSrv},
	}
	if cfg.WebhookListen != "" {
		wtls := tlsConfig()
		if webhookCAs != nil {
			wtls.ClientAuth, wtls.ClientCAs = tls.RequireAndVerifyClientCert, webhookCAs
		}
		servers = append(servers, &listener{setting: "BLASTGATE_WEBHOOK_LISTEN", addr: cfg.WebhookListen, srv: &http.Server{
			// A pointer: the handler holds the in-flight semaphore, and a
			// copy per request would bound nothing.
			Handler:           &webhook.Handler{Rec: bypassRecorder(st), Ignore: cfg.BypassIgnore, Log: log},
			ReadHeaderTimeout: webhookReadHeaderTimeout,
			ReadTimeout:       webhookReadTimeout,
			WriteTimeout:      webhookWriteTimeout,
			IdleTimeout:       webhookIdleTimeout,
			TLSConfig:         wtls,
			ErrorLog:          errorLog,
		}})
	}
	for _, l := range servers[1:] {
		warnUncovered(log, l.setting, l.addr, cfg.TLSHosts)
	}
	// Every address is bound before any is served: one that cannot bind
	// stops the start with the others closed, rather than leaving a proxy
	// running whose approvers have no UI, or a webhook nobody notices is
	// missing.
	for i, l := range servers {
		ln, err := net.Listen("tcp", l.addr)
		if err != nil {
			for _, prev := range servers[:i] {
				prev.ln.Close()
			}
			fmt.Fprintf(stderr, "%s: %v\n", l.setting, err)
			return 1
		}
		l.ln = ln
	}
	log.Info("listening", "addr", servers[0].ln.Addr().String(), "upstream", up.URL.Host, "policy", policyName, "hold", cfg.Hold.String())
	log.Info("admin listening", "addr", servers[1].ln.Addr().String())
	if len(servers) > 2 {
		log.Info("webhook listening", "addr", servers[2].ln.Addr().String(), "client_cert", webhookCAs != nil)
	}
	errc := make(chan error, len(servers))
	for _, l := range servers {
		go func() {
			if err := l.srv.ServeTLS(l.ln, "", ""); err != nil {
				errc <- fmt.Errorf("%s: %w", l.setting, err)
			}
		}()
	}
	// shutdown stops every server together, each given the same 5s for
	// the requests it is still answering.
	shutdown := func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var wg sync.WaitGroup
		for _, l := range servers {
			wg.Go(func() {
				// Shutdown does not wait for hijacked connections (exec,
				// port-forward); those end when the process does.
				if err := l.srv.Shutdown(sctx); err != nil {
					log.Warn("shutdown", "listener", l.setting, "err", err.Error())
				}
			})
		}
		wg.Wait()
	}
	select {
	case <-ctx.Done():
		shutdown()
		return 0
	case err := <-errc:
		shutdown()
		if errors.Is(err, http.ErrServerClosed) {
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
}

// Timeouts for the admin and webhook listeners. The admin API answers
// small JSON bodies (a replayed policy is at most 64 KiB), and a replay
// is the slowest handler; the webhook's longest honest read is one 8 MiB
// AdmissionReview, and the API server gives the whole call 5s.
const (
	adminReadHeaderTimeout = 10 * time.Second
	adminReadTimeout       = 30 * time.Second
	adminWriteTimeout      = 60 * time.Second
	adminIdleTimeout       = 120 * time.Second

	webhookReadHeaderTimeout = 5 * time.Second
	webhookReadTimeout       = 10 * time.Second
	webhookWriteTimeout      = 10 * time.Second
	webhookIdleTimeout       = 90 * time.Second
)

// listener is one of serve's servers and the address it is bound to.
type listener struct {
	setting, addr string
	srv           *http.Server
	ln            net.Listener
}

// bypassRecorder hands the webhook its store without the typed-nil trap:
// a nil *store.Store boxed into the Recorder interface is not == nil, so
// the handler's nil check would pass it and AppendBypass would panic on
// every bypass instead of logging that nothing records them.
func bypassRecorder(st *store.Store) webhook.Recorder {
	if st == nil {
		return nil
	}
	return st
}

// loadClientCAs reads the PEM CAs whose client certificates the webhook
// will require.
func loadClientCAs(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("BLASTGATE_WEBHOOK_CLIENT_CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("BLASTGATE_WEBHOOK_CLIENT_CA %s holds no PEM certificate", path)
	}
	return pool, nil
}

// warnUncovered logs a listen address the serving certificate does not
// name. It warns rather than refuses: clients may reach the listener by a
// name in BLASTGATE_TLS_HOSTS that differs from the address it binds
// (gate.internal in front of 10.0.0.5), which only the operator knows.
// An address that binds every interface names no host to check.
func warnUncovered(log *slog.Logger, setting, addr string, hosts []string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || unspecifiedHost(addr) || covered(host, hosts) {
		return
	}
	log.Warn("the serving certificate does not cover this listen address; clients that reach it by this address will fail TLS verification (add it to BLASTGATE_TLS_HOSTS)",
		"setting", setting, "addr", addr, "tls_hosts", strings.Join(hosts, ","))
}

// approvalsAdapter is gate.Approvals over the approval service and the
// store. Verify passes the authenticated session, human and agent
// straight through (ruling P1-R9).
type approvalsAdapter struct {
	svc *approval.Service
	st  *store.Store
}

func (a approvalsAdapter) Verify(ctx context.Context, session, human, agent, requestDigest, impactDigest string) (approval.Outcome, store.Approval, error) {
	return a.svc.Verify(ctx, session, human, agent, requestDigest, impactDigest)
}

func (a approvalsAdapter) Consume(ctx context.Context, ap store.Approval) error {
	return a.svc.Consume(ctx, ap)
}

// CreatePending stamps the pending lifetime (ruling P1-R16). The gate
// leaves Expires zero, and a zero expiry is the Unix epoch: the approval
// would be born expired, no human could approve it, and every retry would
// mint another.
func (a approvalsAdapter) CreatePending(ctx context.Context, ap store.Approval) error {
	ap.Expires = a.svc.Now().Add(a.svc.PendingTTL)
	return a.st.CreateApproval(ctx, ap)
}

func (a approvalsAdapter) Status(ctx context.Context, id string) (string, error) {
	ap, err := a.st.ApprovalByID(ctx, id)
	if err != nil {
		return "", err
	}
	return ap.Status, nil
}

// soundingSnapshot is snapshot.Taker's SoundingScore: sounding scores the
// delete again with a snapshot directory, writing the undo bundle for the
// cascade it finds. Fresh clients per call, as the engine uses, because
// sounding's Clients is not safe for concurrent scoring.
func soundingSnapshot(cfg *rest.Config) func(context.Context, model.Action, string) error {
	return func(ctx context.Context, act model.Action, dir string) error {
		if cfg == nil {
			// NewForConfig panics on nil; the error refuses the write instead.
			return errors.New("no upstream config to snapshot with")
		}
		c, err := cluster.NewForConfig(cfg)
		if err != nil {
			return err
		}
		_, err = score.Score(ctx, c, act, score.Options{SnapshotDir: dir})
		return err
	}
}
