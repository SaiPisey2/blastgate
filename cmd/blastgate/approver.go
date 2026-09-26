package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/SaiPisey2/blastgate/internal/admin"
	"github.com/SaiPisey2/blastgate/internal/config"
	"github.com/SaiPisey2/blastgate/internal/session"
	"github.com/SaiPisey2/blastgate/internal/store"
)

// approverCmd manages who may sign in to the approver UI. There is no
// default account: until `approver new` has run, nobody can log in.
func approverCmd(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	const usage = "usage: blastgate approver new --name <name> | list | revoke <id>"
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
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
		fs := flag.NewFlagSet("approver new", flag.ContinueOnError)
		fs.SetOutput(stderr)
		name := fs.String("name", "", "the approver's name, recorded on every decision they make (required)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if fs.NArg() != 0 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		// The name is who decided, in the same trail and logs as the
		// humans agents act for, so it passes the same check.
		if err := session.ValidateHuman(*name); err != nil {
			fmt.Fprintf(stderr, "approver name: %v\n", err)
			return 2
		}
		return approverNew(ctx, st, *name, stdout, stderr)

	case "list":
		if len(args) != 1 {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		l, err := st.ListApprovers(ctx)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tCREATED\tSTATE")
		for _, a := range l {
			state := "active"
			if !a.Revoked.IsZero() {
				state = "revoked"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.ID, a.Name, a.Created.Format(time.RFC3339), state)
		}
		tw.Flush()
		return 0

	case "revoke":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: blastgate approver revoke <id>")
			return 2
		}
		// Revoking also ends every UI session the approver holds, in the
		// same transaction: a browser already signed in stops working now.
		err := st.RevokeApprover(ctx, args[1], time.Now().UTC())
		if errors.Is(err, store.ErrNotFound) {
			fmt.Fprintf(stderr, "no approver %q\n", args[1])
			return 1
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stderr, "approver %s revoked, and their UI sessions ended\n", args[1])
		return 0

	default:
		fmt.Fprintf(stderr, "unknown approver command %q\n%s\n", args[0], usage)
		return 2
	}
}

// approverNew creates the approver and prints their login token. The
// token alone goes to stdout, so `blastgate approver new --name bob >
// bob.token` keeps it out of scrollback and any log capturing stderr;
// only its hash is stored, so this is the one time anyone sees it.
func approverNew(ctx context.Context, st *store.Store, name string, stdout, stderr io.Writer) int {
	id := make([]byte, 8)
	rand.Read(id)
	a := store.Approver{ID: hex.EncodeToString(id), Name: name, Created: time.Now().UTC()}
	tok, hash := admin.NewLoginToken()
	err := st.CreateApprover(ctx, a, hash)
	if errors.Is(err, store.ErrConflict) {
		fmt.Fprintf(stderr, "an approver named %q is already active; revoke them first (blastgate approver list shows the id)\n", name)
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := fmt.Fprintln(stdout, tok); err != nil {
		// The token was never delivered, or only part of it: nobody
		// should hold a live login they cannot see.
		fmt.Fprintf(stderr, "writing the token: %v\n", err)
		if rerr := st.RevokeApprover(ctx, a.ID, time.Now().UTC()); rerr != nil {
			fmt.Fprintf(stderr, "approver %s could not be revoked: %v; revoke it with: blastgate approver revoke %[1]s\n", a.ID, rerr)
		} else {
			fmt.Fprintf(stderr, "approver %s revoked\n", a.ID)
		}
		return 1
	}
	fmt.Fprintf(stderr, "approver %s: %s; the token above is shown once, sign in with it at the admin UI\n", a.ID, a.Name)
	return 0
}
