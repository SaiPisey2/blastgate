package approval

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/SaiPisey2/blastgate/internal/store"
)

var key = []byte("3f9a1c07d24be85f6a0913c7e2d84b5f70a6c31e9d28f4b1")

// svc also returns the database path, so a test can open the same file
// behind the store's back the way an attacker with write access would.
func svc(t *testing.T, now *time.Time) (*Service, *store.Store, string) {
	path := filepath.Join(t.TempDir(), "bg.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Service{Store: st, Key: key, TokenTTL: 15 * time.Minute, PendingTTL: time.Hour, Now: func() time.Time { return *now }}, st, path
}

func pending(t *testing.T, st *store.Store, now time.Time) store.Approval {
	a := store.Approval{ID: NewID(), Session: "s1", Human: "alice", Agent: "coding-agent", RequestDigest: "rd", ImpactDigest: "impact-1",
		ActionJSON: []byte(`{}`), ImpactJSON: []byte(`{}`), Rule: "data-destruction", Status: "pending", Created: now, Expires: now.Add(time.Hour)}
	if err := st.CreateApproval(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	return a
}

// tamperImpactDigest edits the row directly with database/sql rather than
// through a store hook, so production code carries no test-only way in.
// It fails unless exactly one row changed: a silent no-op would let
// TestTamperedRowIsVoid pass without ever testing a tampered row.
func tamperImpactDigest(path, id, digest string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	res, err := db.Exec(`UPDATE approvals SET impact_digest = ? WHERE id = ?`, digest, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return store.ErrNotFound
	}
	return nil
}

func TestApprovedRetryWithSameImpactIsReleasedOnce(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	if _, err := s.Approve(context.Background(), a.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	o, _, err := s.Check(context.Background(), "s1", "coding-agent", "rd", "impact-1")
	if err != nil || o != Release {
		t.Fatalf("first check = %v, %v", o, err)
	}
	if o, _, _ := s.Check(context.Background(), "s1", "coding-agent", "rd", "impact-1"); o != None {
		t.Errorf("second check = %v, want None (token already spent)", o)
	}
}

func TestVerifyFailsWhenImpactChanged(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	s.Approve(context.Background(), a.ID, "bob")
	o, got, _ := s.Check(context.Background(), "s1", "coding-agent", "rd", "impact-2")
	if o != Void {
		t.Fatalf("check = %v, want Void", o)
	}
	if row, _ := st.ApprovalByID(context.Background(), got.ID); row.Status != "superseded" {
		t.Errorf("status = %q, want superseded", row.Status)
	}
}

func TestAnotherAgentCannotUseTheApproval(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	s.Approve(context.Background(), a.ID, "bob")
	if o, _, _ := s.Check(context.Background(), "s1", "other-agent", "rd", "impact-1"); o == Release {
		t.Error("an approval for one agent released another's request")
	}
}

func TestExpiredTokenIsNotReleased(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	s.Approve(context.Background(), a.ID, "bob")
	now = now.Add(16 * time.Minute)
	if o, _, _ := s.Check(context.Background(), "s1", "coding-agent", "rd", "impact-1"); o != None {
		t.Errorf("check after expiry = %v", o)
	}
}

func TestPendingAndDenied(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	if o, _, _ := s.Check(context.Background(), "s1", "coding-agent", "rd", "impact-1"); o != Pending {
		t.Errorf("pending check = %v", o)
	}
	s.Deny(context.Background(), a.ID, "bob")
	if o, _, _ := s.Check(context.Background(), "s1", "coding-agent", "rd", "impact-1"); o != Denied {
		t.Errorf("denied check = %v", o)
	}
	now = now.Add(2 * time.Hour)
	if o, _, _ := s.Check(context.Background(), "s1", "coding-agent", "rd", "impact-1"); o != None {
		t.Errorf("stale denial still blocks: %v", o)
	}
}

// Tampering with the stored impact digest to match a new measurement must
// not release: the token was computed over the approved digest.
func TestTamperedRowIsVoid(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, path := svc(t, &now)
	a := pending(t, st, now)
	s.Approve(context.Background(), a.ID, "bob")
	// simulate an attacker with DB write access changing impact_digest
	if err := tamperImpactDigest(path, a.ID, "impact-2"); err != nil {
		t.Fatal(err)
	}
	if o, _, _ := s.Check(context.Background(), "s1", "coding-agent", "rd", "impact-2"); o == Release {
		t.Error("a row edited to match a new impact was released")
	}
}

func TestTokenDependsOnEveryField(t *testing.T) {
	s := &Service{Key: key}
	base := store.Approval{ID: "id", Agent: "a", RequestDigest: "r", ImpactDigest: "i"}
	exp := time.Unix(100, 0)
	t0 := s.Token(base, "n", exp)
	for name, mut := range map[string]func(*store.Approval){
		"id": func(a *store.Approval) { a.ID = "x" }, "agent": func(a *store.Approval) { a.Agent = "x" },
		"request": func(a *store.Approval) { a.RequestDigest = "x" }, "impact": func(a *store.Approval) { a.ImpactDigest = "x" },
	} {
		c := base
		mut(&c)
		if s.Token(c, "n", exp) == t0 {
			t.Errorf("token ignores %s", name)
		}
	}
	if s.Token(base, "m", exp) == t0 || s.Token(base, "n", exp.Add(time.Millisecond)) == t0 {
		t.Error("token ignores nonce or expiry")
	}
}

// A pending approval nobody acted on must stop blocking once its hour is
// up, and be recorded as expired rather than left pending forever.
func TestStalePendingExpires(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	now = now.Add(time.Hour + time.Millisecond)
	if o, _, err := s.Check(context.Background(), "s1", "coding-agent", "rd", "impact-1"); err != nil || o != None {
		t.Fatalf("check on stale pending = %v, %v", o, err)
	}
	if row, _ := st.ApprovalByID(context.Background(), a.ID); row.Status != "expired" {
		t.Errorf("status = %q, want expired", row.Status)
	}
}

// Approving an approval that is no longer pending, or whose pending hour
// has run out, must fail rather than mint a token for it.
func TestApproveRefusesDecidedOrStale(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	if _, err := s.Deny(context.Background(), a.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(context.Background(), a.ID, "carol"); err == nil {
		t.Error("approved a denied approval")
	}
	b := pending(t, st, now)
	now = now.Add(2 * time.Hour)
	if _, err := s.Approve(context.Background(), b.ID, "carol"); err == nil {
		t.Error("approved a pending approval past its expiry")
	}
	if row, _ := st.ApprovalByID(context.Background(), b.ID); row.Token != "" {
		t.Error("a token was stored for a stale approval")
	}
}

// Without a key every token is computable by anyone, so the service must
// refuse to mint or honour one rather than run unauthenticated.
func TestEmptyKeyFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	s.Key = nil
	if _, err := s.Approve(context.Background(), a.ID, "bob"); err == nil {
		t.Error("approved with no signing key")
	}
	if o, _, err := s.Check(context.Background(), "s1", "coding-agent", "rd", "impact-1"); err == nil || o == Release {
		t.Errorf("check with no signing key = %v, %v", o, err)
	}
}
