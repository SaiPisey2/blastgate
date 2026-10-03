package approval

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/SaiPisey2/blastgate/internal/store"
)

// held creates a pending approval for alice whose stored impact is
// impactJSON, so a test picks the class the rules read.
func held(t *testing.T, st *store.Store, now time.Time, impactJSON string) store.Approval {
	t.Helper()
	a := store.Approval{ID: NewID(), Session: "s1", Human: "alice", Agent: "coding-agent", RequestDigest: "rd", ImpactDigest: "impact-1",
		ActionJSON: []byte(`{}`), ImpactJSON: []byte(impactJSON), Rule: "access-grant", Status: "pending", Created: now, Expires: now.Add(time.Hour)}
	if err := st.CreateApproval(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	return a
}

const (
	authority  = `{"class":"AUTHORITY","measured":true}`
	reversible = `{"class":"REVERSIBLE","measured":true}`
)

func browser(id, name string, signedIn time.Time) Approver {
	return Approver{ID: id, Name: name, SignedIn: signedIn, Channel: "ui"}
}

func cli(name string) Approver { return Approver{Name: name, Channel: "cli"} }

func row(t *testing.T, st *store.Store, id string) store.Approval {
	t.Helper()
	a, err := st.ApprovalByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestSelfApproval(t *testing.T) {
	ctx := context.Background()
	t.Run("self approval by name is refused", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		a := held(t, st, now, reversible)
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "alice", now)); !errors.Is(err, ErrSelfApproval) {
			t.Fatalf("alice approving her own request: %v, want ErrSelfApproval", err)
		}
		// Exact and case-sensitive, as names are recorded: Alice is not alice.
		if _, err := s.Approve(ctx, a.ID, browser("ap2", "Alice", now)); err != nil {
			t.Fatalf("Alice approving alice's request: %v", err)
		}
	})
	t.Run("self approval by linked human is refused", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		a := held(t, st, now, authority)
		by := browser("ap1", "al", now)
		by.Humans = []string{"bob", "alice"}
		if _, err := s.Approve(ctx, a.ID, by); !errors.Is(err, ErrSelfApproval) {
			t.Fatalf("approver linked to alice: %v, want ErrSelfApproval", err)
		}
		if r := row(t, st, a.ID); r.Status != "pending" || r.FirstApproverID != "" {
			t.Errorf("a refused self approval moved the row: %+v", r)
		}
	})
	t.Run("cli self approval is refused", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		a := held(t, st, now, reversible)
		if _, err := s.Approve(ctx, a.ID, cli("alice")); !errors.Is(err, ErrSelfApproval) {
			t.Fatalf("cli approve by alice: %v, want ErrSelfApproval", err)
		}
		if r := row(t, st, a.ID); r.Status != "pending" || r.Token != "" {
			t.Errorf("a refused self approval minted: %+v", r)
		}
	})
	t.Run("deny is never blocked by self approval", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		a := held(t, st, now, authority)
		if _, err := s.Deny(ctx, a.ID, "alice"); err != nil {
			t.Fatalf("alice denying her own request: %v", err)
		}
		if r := row(t, st, a.ID); r.Status != "denied" {
			t.Errorf("status %s, want denied", r.Status)
		}
	})
}

func TestTwoPeople(t *testing.T) {
	ctx := context.Background()
	t.Run("access grants need two different accounts", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		a := held(t, st, now, authority)
		first, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now))
		if err != nil {
			t.Fatal(err)
		}
		if first.Status != "partially_approved" || first.Token != "" || first.Nonce != "" ||
			first.FirstApproverID != "ap1" || first.FirstApproverName != "bob" || !first.FirstApproved.Equal(now) {
			t.Fatalf("after the first approval: %+v", first)
		}
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now)); !errors.Is(err, ErrNeedsSecondApprover) {
			t.Fatalf("same account again: %v, want ErrNeedsSecondApprover", err)
		}
		// A second account under the same display name is still the same
		// person only if the id matches; the id is what is compared.
		if _, err := s.Approve(ctx, a.ID, browser("", "carol", now)); !errors.Is(err, ErrNeedsSecondApprover) {
			t.Fatalf("an approver with no id: %v, want ErrNeedsSecondApprover", err)
		}
		if r := row(t, st, a.ID); r.Status != "partially_approved" || r.Token != "" {
			t.Fatalf("refused second approvals moved the row: %+v", r)
		}
		second, err := s.Approve(ctx, a.ID, browser("ap2", "carol", now))
		if err != nil {
			t.Fatal(err)
		}
		if second.Status != "approved" || second.Nonce == "" || second.Token == "" || second.DecidedBy != "carol" ||
			second.FirstApproverName != "bob" {
			t.Fatalf("after the second approval: %+v", second)
		}
		if o, _, err := s.Check(ctx, "s1", "alice", "coding-agent", "rd", "impact-1"); err != nil || o != Release {
			t.Fatalf("check after two approvals = %v, %v, want Release", o, err)
		}
	})
	t.Run("cli cannot approve an access grant but can deny it", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		a := held(t, st, now, authority)
		if _, err := s.Approve(ctx, a.ID, cli("bob")); !errors.Is(err, ErrChannelNotAllowed) {
			t.Fatalf("cli approve of an access grant: %v, want ErrChannelNotAllowed", err)
		}
		// Not from the cli as the second person either.
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Approve(ctx, a.ID, cli("carol")); !errors.Is(err, ErrChannelNotAllowed) {
			t.Fatalf("cli second approval: %v, want ErrChannelNotAllowed", err)
		}
		if _, err := s.Deny(ctx, a.ID, "carol"); err != nil {
			t.Fatalf("cli deny of an access grant: %v", err)
		}
		if r := row(t, st, a.ID); r.Status != "denied" || r.Token != "" {
			t.Errorf("after cli deny: %+v", r)
		}
	})
	t.Run("reauth window edges", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		s.Reauth = 10 * time.Minute
		a := held(t, st, now, authority)
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now.Add(-10*time.Minute-time.Nanosecond))); !errors.Is(err, ErrReauthRequired) {
			t.Fatalf("signed in Reauth+1ns ago: %v, want ErrReauthRequired", err)
		}
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now.Add(time.Nanosecond))); !errors.Is(err, ErrReauthRequired) {
			t.Fatalf("signed in in the future: %v, want ErrReauthRequired", err)
		}
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", time.Time{})); !errors.Is(err, ErrReauthRequired) {
			t.Fatalf("no sign-in time: %v, want ErrReauthRequired", err)
		}
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now.Add(-10*time.Minute))); err != nil {
			t.Fatalf("signed in exactly Reauth ago: %v", err)
		}
		// The second person is held to the window too.
		if _, err := s.Approve(ctx, a.ID, browser("ap2", "carol", now.Add(-10*time.Minute-time.Nanosecond))); !errors.Is(err, ErrReauthRequired) {
			t.Fatalf("second approver signed in Reauth+1ns ago: %v, want ErrReauthRequired", err)
		}
		if _, err := s.Approve(ctx, a.ID, browser("ap2", "carol", now.Add(-10*time.Minute))); err != nil {
			t.Fatalf("second approver signed in exactly Reauth ago: %v", err)
		}
	})
	t.Run("reauth defaults to fifteen minutes", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		a := held(t, st, now, authority)
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now.Add(-15*time.Minute-time.Nanosecond))); !errors.Is(err, ErrReauthRequired) {
			t.Fatalf("zero Reauth, signed in 15m+1ns ago: %v, want ErrReauthRequired", err)
		}
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now.Add(-15*time.Minute))); err != nil {
			t.Fatalf("zero Reauth, signed in 15m ago: %v", err)
		}
	})
	t.Run("deny after the first approval denies it", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		a := held(t, st, now, authority)
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Deny(ctx, a.ID, "carol"); err != nil {
			t.Fatal(err)
		}
		if r := row(t, st, a.ID); r.Status != "denied" || r.Token != "" || r.DecidedBy != "carol" {
			t.Fatalf("after deny: %+v", r)
		}
		if _, err := s.Approve(ctx, a.ID, browser("ap2", "dave", now)); !errors.Is(err, ErrNotPending) {
			t.Fatalf("approving a denied grant: %v, want ErrNotPending", err)
		}
		if o, _, err := s.Check(ctx, "s1", "alice", "coding-agent", "rd", "impact-1"); err != nil || o != Denied {
			t.Fatalf("check after deny = %v, %v, want Denied", o, err)
		}
	})
	t.Run("unreadable impact needs two approvers", func(t *testing.T) {
		for _, imp := range []string{``, `{}`, `null`, `not json`, `{"class":""}`, `{"class":7}`, `{"class":"authority"}`, `{"class":"SOMETHING_NEW"}`} {
			now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
			s, st, _ := svc(t, &now)
			a := held(t, st, now, imp)
			if !NeedsTwo(a) {
				t.Errorf("NeedsTwo(%q) = false, want true", imp)
			}
			if _, err := s.Approve(ctx, a.ID, cli("bob")); !errors.Is(err, ErrChannelNotAllowed) {
				t.Errorf("impact %q, cli approve: %v, want ErrChannelNotAllowed", imp, err)
			}
			if r, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now)); err != nil || r.Status != "partially_approved" || r.Token != "" {
				t.Errorf("impact %q, first browser approve: %+v, %v, want partial", imp, r, err)
			}
		}
		for _, imp := range []string{reversible, `{"class":"READ"}`, `{"class":"COMPENSABLE"}`, `{"class":"TERMINAL"}`} {
			if NeedsTwo(store.Approval{ImpactJSON: []byte(imp)}) {
				t.Errorf("NeedsTwo(%q) = true, want false", imp)
			}
		}
	})
	t.Run("a partial approval survives the first approver's revocation", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		for i, name := range []string{"bob", "carol"} {
			if err := st.CreateApprover(ctx, store.Approver{ID: "ap" + string(rune('1'+i)), Name: name, Created: now}, []byte(name+"-token-hash")); err != nil {
				t.Fatal(err)
			}
		}
		a := held(t, st, now, authority)
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now)); err != nil {
			t.Fatal(err)
		}
		if err := st.RevokeApprover(ctx, "ap1", now); err != nil {
			t.Fatal(err)
		}
		r := row(t, st, a.ID)
		if r.Status != "partially_approved" || r.FirstApproverID != "ap1" || r.FirstApproverName != "bob" {
			t.Fatalf("revocation changed the partial approval: %+v", r)
		}
		// The revoked account still counts as the first person: signing in
		// again under it cannot supply the second approval.
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now)); !errors.Is(err, ErrNeedsSecondApprover) {
			t.Fatalf("first approver again after revocation: %v, want ErrNeedsSecondApprover", err)
		}
		if r, err := s.Approve(ctx, a.ID, browser("ap2", "carol", now)); err != nil || r.Status != "approved" || r.Token == "" {
			t.Fatalf("second approver: %+v, %v", r, err)
		}
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now)); !errors.Is(err, ErrNotPending) {
			t.Fatalf("first approver after release: %v, want ErrNotPending", err)
		}
	})
	t.Run("concurrent second approvals mint one token", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		a := held(t, st, now, authority)
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now)); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		results := make([]store.Approval, 2)
		errs := make([]error, 2)
		for i, by := range []Approver{browser("ap2", "carol", now), browser("ap3", "dave", now)} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[i], errs[i] = s.Approve(ctx, a.ID, by)
			}()
		}
		wg.Wait()
		won := -1
		for i, err := range errs {
			switch {
			case err == nil:
				if won != -1 {
					t.Fatal("both second approvals succeeded")
				}
				won = i
			case errors.Is(err, ErrNotPending), errors.Is(err, store.ErrConflict):
			default:
				t.Fatalf("losing second approval: %v", err)
			}
		}
		if won == -1 {
			t.Fatalf("neither second approval succeeded: %v", errs)
		}
		r := row(t, st, a.ID)
		if r.Status != "approved" || r.Token != results[won].Token || r.Nonce != results[won].Nonce || r.DecidedBy != results[won].DecidedBy {
			t.Fatalf("stored %+v, winner %+v", r, results[won])
		}
	})
	t.Run("an expired access grant is refused and not marked", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		a := held(t, st, now, authority)
		now = now.Add(time.Hour + time.Millisecond)
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now)); !errors.Is(err, ErrNotPending) {
			t.Fatalf("approving an expired grant: %v, want ErrNotPending", err)
		}
		if r := row(t, st, a.ID); r.Status != "pending" || r.FirstApproverID != "" || !r.FirstApproved.IsZero() {
			t.Fatalf("an expired grant was marked: %+v", r)
		}
	})
}

func TestWaitingState(t *testing.T) {
	ctx := context.Background()
	t.Run("partial expires like pending", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		a := held(t, st, now, authority)
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now)); err != nil {
			t.Fatal(err)
		}
		// Same deadline as pending: the creation-time expiry, not reset by
		// the first approval.
		now = now.Add(time.Hour + time.Millisecond)
		if _, err := s.Approve(ctx, a.ID, browser("ap2", "carol", now)); !errors.Is(err, ErrNotPending) {
			t.Fatalf("second approval of an expired partial: %v, want ErrNotPending", err)
		}
		if _, err := s.Deny(ctx, a.ID, "carol"); !errors.Is(err, ErrNotPending) {
			t.Fatalf("deny of an expired partial: %v, want ErrNotPending", err)
		}
		if r := row(t, st, a.ID); r.Token != "" {
			t.Fatalf("an expired partial was minted: %+v", r)
		}
		o, got, err := s.Verify(ctx, "s1", "alice", "coding-agent", "rd", "impact-1")
		if err != nil || o != None || got.Status != "expired" {
			t.Fatalf("verify of an expired partial = %v, %s, %v, want None, expired", o, got.Status, err)
		}
		if r := row(t, st, a.ID); r.Status != "expired" {
			t.Fatalf("stored status %s, want expired", r.Status)
		}
	})
	t.Run("verify treats partial as waiting", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		a := held(t, st, now, authority)
		if _, err := s.Approve(ctx, a.ID, browser("ap1", "bob", now)); err != nil {
			t.Fatal(err)
		}
		o, got, err := s.Verify(ctx, "s1", "alice", "coding-agent", "rd", "impact-1")
		if err != nil || o != Pending || got.ID != a.ID {
			t.Fatalf("verify of a partial = %v, %v, want Pending", o, err)
		}
		if o, _, err := s.Check(ctx, "s1", "alice", "coding-agent", "rd", "impact-1"); err != nil || o != Pending {
			t.Fatalf("check of a partial = %v, %v, want Pending", o, err)
		}
		if r := row(t, st, a.ID); r.Status != "partially_approved" {
			t.Fatalf("verify moved a partial to %s", r.Status)
		}
	})
}

func TestSingleApprover(t *testing.T) {
	ctx := context.Background()
	t.Run("reversible approval still needs one approver and works from the cli", func(t *testing.T) {
		now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
		s, st, _ := svc(t, &now)
		a := held(t, st, now, reversible)
		// No sign-in time and no id: the reauth and second-person rules
		// belong to access grants only.
		r, err := s.Approve(ctx, a.ID, cli("bob"))
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != "approved" || r.Token == "" || r.Nonce == "" || r.DecidedBy != "bob" || r.FirstApproverID != "" {
			t.Fatalf("after one cli approval: %+v", r)
		}
		if o, _, err := s.Check(ctx, "s1", "alice", "coding-agent", "rd", "impact-1"); err != nil || o != Release {
			t.Fatalf("check = %v, %v, want Release", o, err)
		}
		b := held(t, st, now, reversible)
		if r, err := s.Approve(ctx, b.ID, browser("ap1", "bob", now.Add(-24*time.Hour))); err != nil || r.Status != "approved" {
			t.Fatalf("browser approval of a reversible request with an old sign-in: %+v, %v", r, err)
		}
	})
}
