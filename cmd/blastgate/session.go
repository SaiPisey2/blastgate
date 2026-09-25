package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/SaiPisey2/blastgate/internal/config"
	"github.com/SaiPisey2/blastgate/internal/session"
	"github.com/SaiPisey2/blastgate/internal/store"
	"github.com/SaiPisey2/blastgate/internal/tlsutil"
)

// openStore creates dataDir (private: it holds token hashes) and opens the
// database inside it. serve reuses this so both paths agree on the layout.
func openStore(dataDir string) (*store.Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	// MkdirAll leaves an existing directory's mode alone, and a data dir
	// made by hand with the umask's 0755 would expose the TLS directory's
	// listing and whatever the database leaves beside it.
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(dataDir, "blastgate.db"))
}

func sessionCmd(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: blastgate session new|list|revoke")
		return 2
	}
	cfg, err := config.LoadLocal(getenv)
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
	ctx := context.Background()

	switch args[0] {
	case "new":
		fs := flag.NewFlagSet("session new", flag.ContinueOnError)
		fs.SetOutput(stderr)
		human := fs.String("human", "", "the person the agent acts for (required)")
		agent := fs.String("agent", "", "the agent's name, e.g. coding-agent (required)")
		ttl := fs.Duration("ttl", 8*time.Hour, "how long the session lasts")
		server := fs.String("server", "https://"+cfg.Listen, "the address kubectl reaches blastgate at")
		ns := fs.String("namespace", "", "default namespace for the kubeconfig's context")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		serverSet := false
		fs.Visit(func(f *flag.Flag) { serverSet = serverSet || f.Name == "server" })
		if !serverSet && unspecifiedHost(cfg.Listen) {
			// https://0.0.0.0:8443 is where blastgate listens, not an
			// address kubectl can reach it at; defaulting to it would print
			// a kubeconfig that fails, or worse, reaches another machine's
			// service by that name.
			fmt.Fprintf(stderr, "BLASTGATE_LISTEN %q listens on every address; pass --server with the address kubectl should use, e.g. --server https://gate.internal:8443\n", cfg.Listen)
			return 2
		}
		// The CA is generated on first use so `session new` works before
		// `serve` has ever run, and every kubeconfig it prints trusts it.
		_, caPEM, err := tlsutil.LoadOrCreate(filepath.Join(cfg.DataDir, "tls"), cfg.TLSHosts)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		s, tok, err := session.New(*human, *agent, *ttl, time.Now().UTC())
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		if err := st.CreateSession(ctx, s, session.Hash(tok)); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		kc, err := session.Kubeconfig(*server, caPEM, tok, *ns, s)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		// The kubeconfig (and the token inside it) goes to stdout only, so
		// `blastgate session new … > agent.kubeconfig` never leaks it into a
		// terminal's scrollback or a log capturing stderr.
		if _, err := stdout.Write(kc); err != nil {
			// The token was never delivered, or only part of it: nobody
			// should be holding a live session they cannot see.
			fmt.Fprintf(stderr, "writing the kubeconfig: %v\n", err)
			if rerr := st.RevokeSession(ctx, s.ID, time.Now().UTC()); rerr != nil {
				fmt.Fprintf(stderr, "session %s could not be revoked: %v; revoke it with: blastgate session revoke %[1]s\n", s.ID, rerr)
			} else {
				fmt.Fprintf(stderr, "session %s revoked\n", s.ID)
			}
			return 1
		}
		fmt.Fprintf(stderr, "session %s: %s via %s, expires %s\n", s.ID, s.Human, s.Agent, s.Expires.Format(time.RFC3339))
		return 0

	case "list":
		l, err := st.ListSessions(ctx)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		now := time.Now()
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tHUMAN\tAGENT\tEXPIRES\tSTATE")
		for _, s := range l {
			state := "active"
			switch {
			case !s.Revoked.IsZero():
				state = "revoked"
			case !now.Before(s.Expires):
				state = "expired"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.ID, s.Human, s.Agent, s.Expires.Format(time.RFC3339), state)
		}
		tw.Flush()
		return 0

	case "revoke":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: blastgate session revoke <id>")
			return 2
		}
		err := st.RevokeSession(ctx, args[1], time.Now().UTC())
		if errors.Is(err, store.ErrNotFound) {
			fmt.Fprintf(stderr, "no session %q\n", args[1])
			return 2
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stderr, "session %s revoked\n", args[1])
		return 0

	default:
		fmt.Fprintf(stderr, "unknown session command %q\n", args[0])
		return 2
	}
}

// unspecifiedHost reports a listen address that binds every interface:
// an empty host, 0.0.0.0 or ::.
func unspecifiedHost(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}
