package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"k8s.io/client-go/rest"

	"github.com/SaiPisey2/sounding/pkg/cluster"
	"github.com/SaiPisey2/sounding/pkg/model"
	"github.com/SaiPisey2/sounding/pkg/score"

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
)

// serveCmd wires config, store, TLS, upstream and proxy into a running
// HTTPS server, and shuts it down cleanly when ctx is cancelled. Logging is
// JSON: the proxy logs attacker-chosen header names, and JSON escaping
// keeps those safe in the log stream.
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
	if cfg.PolicyPath != "" {
		if pol, err = loadPolicy(cfg.PolicyPath); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		policyName = cfg.PolicyPath
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
		Hold: cfg.Hold,
		Poll: 500 * time.Millisecond,
		Log:  log,
	}
	srv := &http.Server{
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
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ErrorLog:    slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	log.Info("listening", "addr", ln.Addr().String(), "upstream", up.URL.Host, "policy", policyName, "hold", cfg.Hold.String())
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Shutdown does not wait for hijacked connections (exec, port-
		// forward); those end when the process does.
		if err := srv.Shutdown(sctx); err != nil {
			log.Warn("shutdown", "err", err.Error())
		}
		return 0
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 1
	}
}

// approvalsAdapter is gate.Approvals over the approval service and the
// store. Check passes the authenticated session, human and agent straight
// through (ruling P1-R9).
type approvalsAdapter struct {
	svc *approval.Service
	st  *store.Store
}

func (a approvalsAdapter) Check(ctx context.Context, session, human, agent, requestDigest, impactDigest string) (approval.Outcome, store.Approval, error) {
	return a.svc.Check(ctx, session, human, agent, requestDigest, impactDigest)
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
