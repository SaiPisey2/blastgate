package store_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/SaiPisey2/blastgate/internal/approval"
	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/store"
)

// An access grant approved by a single person under v0.3.0, its token
// still live, is not voided by the upgrade: the token binds the request
// and impact, not who approved it, so the retry still releases it until
// the token lapses. The README's upgrade note says exactly this; the test
// pins it so the note and the code cannot drift apart. A grant still
// pending at the upgrade needs two people from then on.
func TestV030ApprovedAccessGrantStillReleasesUntilItsTokenLapses(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	now := t0.Add(2 * time.Minute)
	key := []byte("0c5e2f8a1b9d47e3a6f0c2d8b4e7a1f9c3d5e8b2a4f6c0d1")
	p := filepath.Join(t.TempDir(), "blastgate.db")

	imp := engine.Impact{Class: engine.ClassAuthority, Measured: true}
	impJSON, _ := json.Marshal(imp)
	svc := &approval.Service{Key: key, TokenTTL: 15 * time.Minute, PendingTTL: time.Hour, Now: func() time.Time { return now }}
	granted := store.Approval{ID: "a1", Session: "s1", Human: "alice", Agent: "coding-agent", RequestDigest: "rd1", ImpactDigest: imp.Digest()}
	nonce, expires := "n1", t0.Add(16*time.Minute)
	token := svc.Token(granted, nonce, expires)

	// The database as v0.3.0 left it: four migrations, one access grant
	// approved by bob alone, one still pending.
	db, err := sql.Open("sqlite", "file:"+p+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for i, m := range store.V030Migrations {
		if _, err := db.ExecContext(ctx, m); err != nil {
			t.Fatalf("migration %d: %v", i+1, err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (?)`, i+1); err != nil {
			t.Fatal(err)
		}
	}
	ins := `INSERT INTO approvals (id, session_id, human, agent, request_digest, impact_digest,
		action_json, impact_json, rule, status, created_at, decided_at, decided_by, nonce, token, expires_at)
		VALUES (?,?,?,?,?,?,'{}',?,'access-grant',?,?,?,?,?,?,?)`
	if _, err := db.ExecContext(ctx, ins, "a1", "s1", "alice", "coding-agent", "rd1", imp.Digest(), impJSON, "approved",
		t0.UnixMilli(), t0.Add(time.Minute).UnixMilli(), "bob", nonce, token, expires.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, ins, "a2", "s1", "alice", "coding-agent", "rd2", imp.Digest(), impJSON, "pending",
		t0.UnixMilli(), nil, "", "", "", t0.Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err := store.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc.Store = st

	pend, err := st.ApprovalByID(ctx, "a2")
	if err != nil {
		t.Fatal(err)
	}
	if !approval.NeedsTwo(pend) {
		t.Error("a v0.3.0 pending access grant does not need two approvers after the upgrade")
	}
	if _, err := svc.Approve(ctx, "a2", approval.Approver{Name: "bob", Channel: "cli"}); err != approval.ErrChannelNotAllowed {
		t.Errorf("cli approve of a v0.3.0 pending grant: %v, want ErrChannelNotAllowed", err)
	}

	// The lapsed case first, on a copy of the clock: past its expiry the
	// v0.3.0 token releases nothing.
	late := *svc
	late.Now = func() time.Time { return expires.Add(time.Millisecond) }
	if o, _, err := late.Verify(ctx, "s1", "alice", "coding-agent", "rd1", imp.Digest()); err != nil || o != approval.None {
		t.Fatalf("verify of a lapsed v0.3.0 grant = %v, %v, want None", o, err)
	}
	// Verify moved it to expired; put it back to test the live case on
	// the same row.
	if err := st.SetApprovalStatus(ctx, "a1", "expired", "approved"); err != nil {
		t.Fatal(err)
	}
	if o, _, err := svc.Check(ctx, "s1", "alice", "coding-agent", "rd1", imp.Digest()); err != nil || o != approval.Release {
		t.Fatalf("check of a live v0.3.0 single-approver grant = %v, %v, want Release", o, err)
	}
	if o, _, _ := svc.Check(ctx, "s1", "alice", "coding-agent", "rd1", imp.Digest()); o != approval.None {
		t.Fatalf("second check = %v, want None (spent)", o)
	}
}
