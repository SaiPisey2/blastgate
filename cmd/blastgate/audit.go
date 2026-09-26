package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/SaiPisey2/blastgate/internal/admin"
	"github.com/SaiPisey2/blastgate/internal/config"
)

func auditCmd(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "export" {
		fmt.Fprintln(stderr, "usage: blastgate audit export [--since 24h]")
		return 2
	}
	fs := flag.NewFlagSet("audit export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	since := fs.Duration("since", 24*time.Hour, "how far back to export")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *since <= 0 {
		fmt.Fprintln(stderr, "usage: blastgate audit export [--since 24h]")
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
	rows, err := st.AuditSince(context.Background(), time.Now().Add(-*since), "")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	w := bufio.NewWriter(stdout)
	enc := json.NewEncoder(w)
	for _, r := range rows {
		if err := enc.Encode(admin.ToExport(r)); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if err := w.Flush(); err != nil {
		// A truncated export read as complete would hide the rows after
		// the cut from whoever audits it.
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
