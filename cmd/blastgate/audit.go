package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/SaiPisey2/blastgate/internal/config"
	"github.com/SaiPisey2/blastgate/internal/store"
)

// exportRow is one audit row as exported. Request bodies are never stored
// (only their digest), so none can appear here.
type exportRow struct {
	At            time.Time       `json:"at"`
	Kind          string          `json:"kind"`
	RequestID     string          `json:"request_id"`
	Session       string          `json:"session"`
	Human         string          `json:"human"`
	Agent         string          `json:"agent"`
	Source        string          `json:"source"`
	Verb          string          `json:"verb"`
	Group         string          `json:"group"`
	Resource      string          `json:"resource"`
	Subresource   string          `json:"subresource"`
	Namespace     string          `json:"namespace"`
	Name          string          `json:"name"`
	RequestDigest string          `json:"request_digest"`
	Class         string          `json:"class"`
	Measured      bool            `json:"measured"`
	Rule          string          `json:"rule"`
	Decision      string          `json:"decision"`
	ApprovalID    string          `json:"approval_id"`
	Status        int             `json:"status"`
	Outcome       string          `json:"outcome"`
	LatencyMS     int64           `json:"latency_ms"`
	Snapshot      string          `json:"snapshot"`
	Action        json.RawMessage `json:"action,omitempty"`
	Impact        json.RawMessage `json:"impact,omitempty"`
	Labels        json.RawMessage `json:"labels,omitempty"`
}

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
		if err := enc.Encode(toExport(r)); err != nil {
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

func toExport(r store.AuditRow) exportRow {
	return exportRow{
		At: r.At, Kind: r.Kind, RequestID: r.RequestID, Session: r.Session, Human: r.Human, Agent: r.Agent,
		Source: r.Source, Verb: r.Verb, Group: r.Group, Resource: r.Resource, Subresource: r.Subresource,
		Namespace: r.Namespace, Name: r.Name, RequestDigest: r.RequestDigest, Class: r.Class,
		Measured: r.Measured, Rule: r.Rule, Decision: r.Decision, ApprovalID: r.ApprovalID,
		Status: r.Status, Outcome: r.Outcome, LatencyMS: r.LatencyMS, Snapshot: r.Snapshot,
		Action: rawJSON(r.ActionJSON), Impact: rawJSON(r.ImpactJSON), Labels: rawJSON(r.LabelsJSON),
	}
}

// rawJSON embeds a stored JSON column as itself. An empty column is left
// out; one that is somehow not valid JSON is exported as a string, since
// a RawMessage that is not JSON would fail the whole line.
func rawJSON(b []byte) json.RawMessage {
	if len(b) == 0 {
		return nil
	}
	if json.Valid(b) {
		return json.RawMessage(b)
	}
	s, _ := json.Marshal(string(b))
	return s
}
