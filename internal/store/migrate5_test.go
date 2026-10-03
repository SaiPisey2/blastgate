package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// A database created by v0.3.0 has run exactly the first four migrations.
// It is built here the way migrateOnce builds one, not with the current
// Open, so the test proves migration 5 applies on top of real v0.3.0 rows
// rather than on a fresh schema that never held any.
func TestV030DatabaseMigratesAndKeepsItsRows(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "blastgate.db")
	db, err := sql.Open("sqlite", "file:"+p+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for i, m := range migrations[:4] {
		if _, err := tx.ExecContext(ctx, m); err != nil {
			t.Fatalf("migration %d: %v", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (?)`, i+1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO approvals (id, session_id, human, agent, request_digest, impact_digest,
		action_json, impact_json, rule, status, created_at, decided_at, decided_by, nonce, token, expires_at)
		VALUES ('a1','s1','alice','coding-agent','rd','id','{}','{}','data-destruction','approved',?,?,'bob','n1','tok',?)`,
		ms(t0), ms(t0.Add(time.Minute)), ms(t0.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO approvers (id, name, token_hash, created_at) VALUES ('ap1','bob',X'01',?)`, ms(t0)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// The audit row goes in through a v0.3.0-shaped table too; AppendAudit
	// is unchanged by migration 5, so writing it after a reopen would not
	// prove the old row survived. Open the raw database once more for it.
	db, err = sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	r := row("decision")
	if _, err := db.ExecContext(ctx, `INSERT INTO audit (`+auditCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ms(r.At), r.Kind, r.RequestID, r.Session, r.Human, r.Agent, r.Source,
		r.Verb, r.Group, r.Resource, r.Subresource, r.Namespace, r.Name,
		r.RequestDigest, r.ActionJSON, r.ImpactJSON, r.LabelsJSON,
		r.Class, 1, r.Rule, r.Decision, r.ApprovalID,
		r.Status, r.Outcome, r.LatencyMS, r.Snapshot); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var v int
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_version`).Scan(&v); err != nil || v != 5 {
		t.Fatalf("schema version = %d, %v; want 5", v, err)
	}
	a, err := s.ApprovalByID(ctx, "a1")
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != "approved" || a.DecidedBy != "bob" || a.Nonce != "n1" || a.Token != "tok" || !a.Created.Equal(t0) {
		t.Errorf("approval = %+v", a)
	}
	if a.FirstApproverID != "" || a.FirstApproverName != "" || !a.FirstApproved.IsZero() {
		t.Errorf("new columns not zero: %q %q %v", a.FirstApproverID, a.FirstApproverName, a.FirstApproved)
	}
	aps, err := s.ListApprovers(ctx)
	if err != nil || len(aps) != 1 || aps[0].Name != "bob" {
		t.Errorf("approvers = %+v, %v", aps, err)
	}
	if hs, err := s.ApproverHumans(ctx, "ap1"); err != nil || len(hs) != 0 {
		t.Errorf("approver humans = %v, %v", hs, err)
	}
	rows, err := s.AuditSince(ctx, t0.Add(-time.Hour), "")
	if err != nil || len(rows) != 1 || rows[0].Human != "alice" || rows[0].Rule != "safe" {
		t.Errorf("audit = %+v, %v", rows, err)
	}
}
