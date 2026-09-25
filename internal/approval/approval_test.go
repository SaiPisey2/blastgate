package approval

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
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

// tamper edits one column of an approval row directly with database/sql
// rather than through a store hook, so production code carries no
// test-only way in. It fails unless exactly one row changed: a silent
// no-op would let a tamper test pass without ever testing a tampered row.
// column is always a constant from the calling test, never input.
func tamper(path, id, column string, value any) error {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	res, err := db.Exec(`UPDATE approvals SET `+column+` = ? WHERE id = ?`, value, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return store.ErrNotFound
	}
	return nil
}

func tamperImpactDigest(path, id, digest string) error {
	return tamper(path, id, "impact_digest", digest)
}

func TestApprovedRetryWithSameImpactIsReleasedOnce(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	if _, err := s.Approve(context.Background(), a.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	o, _, err := s.Check(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1")
	if err != nil || o != Release {
		t.Fatalf("first check = %v, %v", o, err)
	}
	if o, _, _ := s.Check(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1"); o != None {
		t.Errorf("second check = %v, want None (token already spent)", o)
	}
}

func TestVerifyFailsWhenImpactChanged(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	if _, err := s.Approve(context.Background(), a.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	o, got, _ := s.Check(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-2")
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
	if _, err := s.Approve(context.Background(), a.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	if o, _, err := s.Check(context.Background(), "s1", "alice", "other-agent", "rd", "impact-1"); err != nil || o != Void {
		t.Errorf("check as another agent = %v, %v, want Void", o, err)
	}
}

func TestExpiredTokenIsNotReleased(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	s.Approve(context.Background(), a.ID, "bob")
	now = now.Add(16 * time.Minute)
	if o, _, _ := s.Check(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1"); o != None {
		t.Errorf("check after expiry = %v", o)
	}
}

func TestPendingAndDenied(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	if o, _, _ := s.Check(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1"); o != Pending {
		t.Errorf("pending check = %v", o)
	}
	s.Deny(context.Background(), a.ID, "bob")
	if o, _, _ := s.Check(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1"); o != Denied {
		t.Errorf("denied check = %v", o)
	}
	now = now.Add(2 * time.Hour)
	if o, _, _ := s.Check(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1"); o != None {
		t.Errorf("stale denial still blocks: %v", o)
	}
}

// Tampering with the stored impact digest to match a new measurement must
// not release: the token was computed over the approved digest.
func TestTamperedRowIsVoid(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, path := svc(t, &now)
	a := pending(t, st, now)
	if _, err := s.Approve(context.Background(), a.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	// simulate an attacker with DB write access changing impact_digest
	if err := tamperImpactDigest(path, a.ID, "impact-2"); err != nil {
		t.Fatal(err)
	}
	if o, _, err := s.Check(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-2"); err != nil || o != Void {
		t.Errorf("check on a row edited to match a new impact = %v, %v, want Void", o, err)
	}
}

func TestTokenDependsOnEveryField(t *testing.T) {
	s := &Service{Key: key}
	base := store.Approval{ID: "id", Session: "s", Human: "h", Agent: "a", RequestDigest: "r", ImpactDigest: "i"}
	exp := time.Unix(100, 0)
	t0 := s.Token(base, "n", exp)
	for name, mut := range map[string]func(*store.Approval){
		"id": func(a *store.Approval) { a.ID = "x" }, "agent": func(a *store.Approval) { a.Agent = "x" },
		"session": func(a *store.Approval) { a.Session = "x" }, "human": func(a *store.Approval) { a.Human = "x" },
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
	s.Key = nil
	if tok := s.Token(base, "n", exp); tok != "" {
		t.Errorf("token minted with no key: %q", tok)
	}
}

// A pending approval nobody acted on must stop blocking once its hour is
// up, and be recorded as expired rather than left pending forever.
func TestStalePendingExpires(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	now = now.Add(time.Hour + time.Millisecond)
	if o, _, err := s.Check(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1"); err != nil || o != None {
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
	if o, _, err := s.Check(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1"); err == nil || o == Release {
		t.Errorf("check with no signing key = %v, %v", o, err)
	}
}

// An approved row moved into another session (another human's, or the
// same human's other agent session) must not release there: the token
// binds the session it was approved in.
func TestApprovalMovedToAnotherSessionIsVoid(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, path := svc(t, &now)
	a := pending(t, st, now)
	if _, err := s.Approve(context.Background(), a.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	if err := tamper(path, a.ID, "session_id", "s2"); err != nil {
		t.Fatal(err)
	}
	if o, _, err := s.Check(context.Background(), "s2", "alice", "coding-agent", "rd", "impact-1"); err != nil || o != Void {
		t.Errorf("check in the session the row was moved to = %v, %v, want Void", o, err)
	}
}

// A different human in the same session cannot use the approval either.
func TestAnotherHumanCannotUseTheApproval(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	if _, err := s.Approve(context.Background(), a.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	if o, _, err := s.Check(context.Background(), "s1", "mallory", "coding-agent", "rd", "impact-1"); err != nil || o != Void {
		t.Errorf("check as another human = %v, %v, want Void", o, err)
	}
}

// Extending expires_at past the token's lifetime, or swapping the nonce
// (say, for one that was never burned), must not release: both are
// inside the HMAC, so an edit the key did not sign fails verification.
func TestTamperedExpiryOrNonceIsVoid(t *testing.T) {
	for _, tc := range []struct {
		column string
		value  func(a store.Approval) any
	}{
		{"expires_at", func(a store.Approval) any { return a.Expires.Add(time.Hour).UnixMilli() }},
		{"nonce", func(store.Approval) any { return NewID() }},
	} {
		t.Run(tc.column, func(t *testing.T) {
			now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
			s, st, path := svc(t, &now)
			a := pending(t, st, now)
			approved, err := s.Approve(context.Background(), a.ID, "bob")
			if err != nil {
				t.Fatal(err)
			}
			if err := tamper(path, a.ID, tc.column, tc.value(approved)); err != nil {
				t.Fatal(err)
			}
			// Past the signed expiry, so only the tampered expires_at
			// could make the row look live.
			if tc.column == "expires_at" {
				now = now.Add(16 * time.Minute)
			}
			if o, _, err := s.Check(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1"); err != nil || o != Void {
				t.Errorf("check after tampering %s = %v, %v, want Void", tc.column, o, err)
			}
		})
	}
}

// Two retries of one approved request racing each other: exactly one may
// forward. The rest see the approval already spent.
func TestConcurrentChecksReleaseOnce(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	if _, err := s.Approve(context.Background(), a.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := map[Outcome]int{}
	var errs []error
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, _, err := s.Check(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1")
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			counts[o]++
		}()
	}
	wg.Wait()
	if len(errs) != 0 {
		t.Errorf("errors: %v", errs)
	}
	if counts[Release] != 1 || counts[None] != 9 {
		t.Errorf("outcomes = %v, want exactly one release and nine none", counts)
	}
}

// Final review I2(a): the gate verifies an approval, snapshots, and only
// then spends it. Verify must leave the approval spendable -- a snapshot
// that fails in between must not burn the human's "yes".
func TestVerifyDoesNotSpend(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	if _, err := s.Approve(context.Background(), a.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		o, got, err := s.Verify(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1")
		if err != nil || o != Verified || got.ID != a.ID {
			t.Fatalf("verify %d = %v, %v", i, o, err)
		}
	}
	if row, _ := st.ApprovalByID(context.Background(), a.ID); row.Status != "approved" {
		t.Errorf("status after verify = %s, want approved", row.Status)
	}
	o, got, _ := s.Verify(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1")
	if o != Verified {
		t.Fatal(o)
	}
	if err := s.Consume(context.Background(), got); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := s.Consume(context.Background(), got); !errors.Is(err, store.ErrConflict) {
		t.Errorf("second consume = %v, want ErrConflict", err)
	}
	if o, _, _ := s.Verify(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1"); o != None {
		t.Errorf("verify after consume = %v, want None", o)
	}
}

// Verify and Consume split across a snapshot: two retries that both
// verified must still release at most once.
func TestConcurrentVerifyThenConsumeReleasesOnce(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	if _, err := s.Approve(context.Background(), a.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	var verified []store.Approval
	for i := 0; i < 10; i++ {
		o, got, err := s.Verify(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1")
		if err != nil || o != Verified {
			t.Fatalf("verify = %v, %v", o, err)
		}
		verified = append(verified, got)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	won, lost := 0, 0
	for _, got := range verified {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Consume(context.Background(), got)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case errors.Is(err, store.ErrConflict):
				lost++
			default:
				t.Errorf("consume: %v", err)
			}
		}()
	}
	wg.Wait()
	if won != 1 || lost != 9 {
		t.Errorf("won %d lost %d, want 1 and 9", won, lost)
	}
}

// A token that lapses between Verify and Consume (a slow snapshot) is not
// spent: it is past the lifetime the approver gave it.
func TestConsumeRefusesALapsedToken(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s, st, _ := svc(t, &now)
	a := pending(t, st, now)
	if _, err := s.Approve(context.Background(), a.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	_, got, _ := s.Verify(context.Background(), "s1", "alice", "coding-agent", "rd", "impact-1")
	now = now.Add(16 * time.Minute)
	if err := s.Consume(context.Background(), got); !errors.Is(err, store.ErrConflict) {
		t.Errorf("consume of a lapsed token = %v, want ErrConflict", err)
	}
}
