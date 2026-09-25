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

	"github.com/SaiPisey2/blastgate/internal/approval"
	"github.com/SaiPisey2/blastgate/internal/config"
	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/gate"
	"github.com/SaiPisey2/blastgate/internal/normalize"
	"github.com/SaiPisey2/blastgate/internal/policy"
	"github.com/SaiPisey2/blastgate/internal/proxy"
	"github.com/SaiPisey2/blastgate/internal/session"
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
	g := &gate.Gate{
		Engine:    engine.New(up, scoreBudget),
		Policy:    policy.Default(),
		Approvals: unavailable{},
		Audit:     st,
		Snapshots: unavailable{},
		Hold:      holdWindow,
		Log:       log,
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
	log.Info("listening", "addr", ln.Addr().String(), "upstream", up.URL.Host)
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

// Until the configuration for them exists, the score budget and hold
// window are the documented defaults.
const (
	scoreBudget = 5 * time.Second
	holdWindow  = 45 * time.Second
)

var errUnavailable = errors.New("not available in this build")

// unavailable stands in for the approval store and the snapshotter until
// they are wired. Every call fails, and the gate refuses on each failure:
// a write policy allows is refused because it cannot be snapshotted, and
// a held write because its approvals cannot be checked. Reads, which need
// neither, still pass and are audited. Nothing is forwarded that the
// finished wiring would refuse.
type unavailable struct{}

func (unavailable) Take(context.Context, string, normalize.Action, engine.Impact) (string, error) {
	return "", errUnavailable
}

func (unavailable) Check(context.Context, string, string, string, string, string) (approval.Outcome, store.Approval, error) {
	return approval.None, store.Approval{}, errUnavailable
}

func (unavailable) CreatePending(context.Context, store.Approval) error { return errUnavailable }

func (unavailable) Status(context.Context, string) (string, error) { return "", errUnavailable }
