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

	"github.com/SaiPisey2/blastgate/internal/config"
	"github.com/SaiPisey2/blastgate/internal/proxy"
	"github.com/SaiPisey2/blastgate/internal/session"
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
	srv := &http.Server{
		Handler:           proxy.New(auth, up, log),
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
