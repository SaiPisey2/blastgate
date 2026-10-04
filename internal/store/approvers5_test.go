package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestApproverHumansAreStoredAndListedSorted(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	for _, a := range []Approver{{ID: "a1", Name: "bob", Created: t0}, {ID: "a2", Name: "carol", Created: t0}} {
		if err := s.CreateApprover(ctx, a, []byte(a.ID)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddApproverHumans(ctx, "a1", []string{"zed@corp", "bob@corp", "Bob@corp"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ApproverHumans(ctx, "a1")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Bob@corp", "bob@corp", "zed@corp"}; !slices.Equal(got, want) {
		t.Errorf("humans = %v, want %v", got, want)
	}
	if got, err := s.ApproverHumans(ctx, "a2"); err != nil || len(got) != 0 {
		t.Errorf("another approver's humans = %v, %v", got, err)
	}
	// The link references approvers(id): a typo'd id must not leave an
	// orphan row that later matches nobody's self-approval check.
	if err := s.AddApproverHumans(ctx, "ghost", []string{"x"}); err == nil {
		t.Error("humans linked to a missing approver")
	}
}

func TestDuplicateApproverHumansAreIgnored(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if err := s.CreateApprover(ctx, Approver{ID: "a1", Name: "bob", Created: t0}, []byte("h")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddApproverHumans(ctx, "a1", []string{"bob@corp", "bob@corp"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddApproverHumans(ctx, "a1", []string{"bob@corp"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ApproverHumans(ctx, "a1"); !slices.Equal(got, []string{"bob@corp"}) {
		t.Errorf("humans = %v", got)
	}
}

func TestSecondApprovalIsConditionalOnPartiallyApproved(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if err := s.CreateApproval(ctx, appr("a1")); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(time.Minute)
	if err := s.MarkPartiallyApproved(ctx, "a1", "ap1", "bob", at); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkPartiallyApproved(ctx, "a1", "ap2", "carol", at.Add(time.Minute)); !errors.Is(err, ErrConflict) {
		t.Errorf("second mark: %v", err)
	}
	if err := s.MarkPartiallyApproved(ctx, "ghost", "ap1", "bob", at); !errors.Is(err, ErrNotFound) {
		t.Errorf("mark of a missing approval: %v", err)
	}
	got, _ := s.ApprovalByID(ctx, "a1")
	if got.Status != "partially_approved" || got.FirstApproverID != "ap1" || got.FirstApproverName != "bob" || !got.FirstApproved.Equal(at) {
		t.Errorf("after first approval = %+v", got)
	}
	// A lone approval needs pending: a partially approved row is an
	// access grant, and only ApproveSecond may release it.
	if err := s.DecideApproval(ctx, "a1", "approved", "carol", "n0", "tok0", t0.Add(2*time.Minute), t0.Add(17*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("lone approve of a partial: %v, want ErrConflict", err)
	}
	// ap1 has no approver account yet: not live, so it cannot be half of
	// a release.
	if err := s.ApproveSecond(ctx, "a1", "ap1", "ap2", "carol", "n0", "tok0", t0.Add(2*time.Minute), t0.Add(17*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("second approval over a first approver with no account: %v, want ErrConflict", err)
	}
	if err := s.CreateApprover(ctx, Approver{ID: "ap1", Name: "bob", Created: t0}, []byte("h-ap1")); err != nil {
		t.Fatal(err)
	}
	// The second approver must be live too: no account, or a revoked
	// one, cannot release.
	if err := s.ApproveSecond(ctx, "a1", "ap1", "ap2", "carol", "n0", "tok0", t0.Add(2*time.Minute), t0.Add(17*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("second approval by an approver with no account: %v, want ErrConflict", err)
	}
	if err := s.CreateApprover(ctx, Approver{ID: "ap5", Name: "erin", Created: t0}, []byte("h-ap5")); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeApprover(ctx, "ap5", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveSecond(ctx, "a1", "ap1", "ap5", "erin", "n0", "tok0", t0.Add(2*time.Minute), t0.Add(17*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("second approval by a revoked approver: %v, want ErrConflict", err)
	}
	if err := s.CreateApprover(ctx, Approver{ID: "ap2", Name: "carol", Created: t0}, []byte("h-ap2")); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveSecond(ctx, "a1", "ap7", "ap2", "carol", "n0", "tok0", t0.Add(2*time.Minute), t0.Add(17*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("second approval pinned to another first approver: %v, want ErrConflict", err)
	}
	if err := s.ApproveSecond(ctx, "a1", "ap1", "ap2", "carol", "n1", "tok", t0.Add(3*time.Minute), t0.Add(18*time.Minute)); err != nil {
		t.Fatalf("decide from partial: %v", err)
	}
	if err := s.ApproveSecond(ctx, "a1", "ap1", "ap3", "dave", "n2", "tok2", t0.Add(4*time.Minute), t0.Add(19*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Errorf("second decide: %v", err)
	}
	got, _ = s.ApprovalByID(ctx, "a1")
	if got.Status != "approved" || got.DecidedBy != "carol" || got.Nonce != "n1" || got.FirstApproverName != "bob" {
		t.Errorf("after second approval = %+v", got)
	}
	// A decided row cannot be dragged back into partial either.
	if err := s.MarkPartiallyApproved(ctx, "a1", "ap3", "erin", t0.Add(5*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Errorf("mark after decide: %v", err)
	}
	var kinds []string
	rows, err := s.db.QueryContext(ctx, `SELECT kind FROM outbox ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		rows.Scan(&k)
		kinds = append(kinds, k)
	}
	if want := []string{"approval.pending", "approval.partial", "approval.decided"}; !slices.Equal(kinds, want) {
		t.Errorf("outbox = %v, want %v", kinds, want)
	}
}

func TestPartialApprovalsArePendingForTheQueueAndTheCount(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	for _, id := range []string{"p", "half", "done"} {
		a := appr(id)
		a.RequestDigest = id
		if err := s.CreateApproval(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MarkPartiallyApproved(ctx, "half", "ap1", "bob", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.DecideApproval(ctx, "done", "denied", "bob", "", "", t0.Add(time.Minute), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	now := t0.Add(2 * time.Minute)
	q, err := s.ListPendingApprovals(ctx, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, a := range q {
		ids = append(ids, a.ID)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"half", "p"}) {
		t.Errorf("queue = %v", ids)
	}
	if n, err := s.CountPendingApprovals(ctx, now); err != nil || n != 2 {
		t.Errorf("count = %d, %v; want 2", n, err)
	}
	// The CLI's `approvals --status pending` and the admin list read
	// ListApprovals: a row waiting on its second approver is still
	// waiting, and must not vanish from them (ruling E-R2).
	for name, list := range map[string]func() ([]Approval, error){
		"ListApprovals":      func() ([]Approval, error) { return s.ListApprovals(ctx, "pending") },
		"ListApprovalsLimit": func() ([]Approval, error) { return s.ListApprovalsLimit(ctx, "pending", 10) },
	} {
		l, err := list()
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, a := range l {
			got = append(got, a.ID)
		}
		slices.Sort(got)
		if !slices.Equal(got, []string{"half", "p"}) {
			t.Errorf("%s(pending) = %v", name, got)
		}
	}
	if l, _ := s.ListApprovals(ctx, "partially_approved"); len(l) != 1 || l[0].ID != "half" {
		t.Errorf("ListApprovals(partially_approved) = %v", l)
	}
	// The live partial filter keeps it while it can be decided, and drops
	// it once lapsed (expires_at < now), as the queue does.
	if l, err := s.ListLivePartialApprovals(ctx, now, 10); err != nil || len(l) != 1 || l[0].ID != "half" {
		t.Errorf("ListLivePartialApprovals(now) = %v, %v", l, err)
	}
	if l, err := s.ListLivePartialApprovals(ctx, t0.Add(time.Hour), 10); err != nil || len(l) != 1 {
		t.Errorf("ListLivePartialApprovals(at expiry) = %v, %v", l, err)
	}
	if l, err := s.ListLivePartialApprovals(ctx, t0.Add(time.Hour+time.Millisecond), 10); err != nil || len(l) != 0 {
		t.Errorf("ListLivePartialApprovals(lapsed) = %v, %v", l, err)
	}
}

func TestCountIgnoresExpired(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	now := t0.Add(time.Hour)
	for _, c := range []struct {
		id      string
		expires time.Duration
		partial bool
	}{
		{"live", 2 * time.Hour, false},
		{"edge", time.Hour, false}, // expires exactly now: still decidable
		{"lapsed", 30 * time.Minute, false},
		{"lapsed-half", 30 * time.Minute, true},
		{"live-half", 2 * time.Hour, true},
	} {
		a := appr(c.id)
		a.RequestDigest, a.Expires = c.id, t0.Add(c.expires)
		if err := s.CreateApproval(ctx, a); err != nil {
			t.Fatal(err)
		}
		if c.partial {
			if err := s.MarkPartiallyApproved(ctx, c.id, "ap1", "bob", t0.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if n, err := s.CountPendingApprovals(ctx, now); err != nil || n != 3 {
		t.Errorf("count = %d, %v; want 3 (live, edge, live-half)", n, err)
	}
	// PendingQueue gives the same rows and the true count past its cap.
	if l, n, err := s.PendingQueue(ctx, now, 2); err != nil || n != 3 || len(l) != 2 {
		t.Errorf("PendingQueue(cap 2) = %d rows, count %d, %v; want 2 rows, count 3", len(l), n, err)
	}
	want, _ := s.ListPendingApprovals(ctx, now, 10)
	if l, n, err := s.PendingQueue(ctx, now, 10); err != nil || n != 3 || len(l) != len(want) {
		t.Errorf("PendingQueue = %v, %d, %v", l, n, err)
	} else {
		for i := range l {
			if l[i].ID != want[i].ID || l[i].Status != want[i].Status || l[i].FirstApproverName != want[i].FirstApproverName {
				t.Errorf("PendingQueue[%d] = %+v, want %+v", i, l[i], want[i])
			}
		}
	}
	if l, n, err := s.PendingQueue(ctx, t0.Add(3*time.Hour), 10); err != nil || n != 0 || len(l) != 0 {
		t.Errorf("PendingQueue(all lapsed) = %v, %d, %v", l, n, err)
	}
}

// A decided or finished hold must never be decided again: a second
// DecideApproval on a consumed, superseded or expired row would mint a
// fresh nonce and token for a request that already ran or was replaced.
func TestDecideRefusesEveryFinishedStatus(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	for _, st := range []string{"approved", "denied", "consumed", "superseded", "expired"} {
		t.Run(st, func(t *testing.T) {
			a := appr("a-" + st)
			a.RequestDigest, a.Status = st, st
			a.Decided, a.DecidedBy, a.Nonce, a.Token = t0.Add(time.Minute), "bob", "n-"+st, "tok-"+st
			if err := s.CreateApproval(ctx, a); err != nil {
				t.Fatal(err)
			}
			before, err := s.ApprovalByID(ctx, a.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, to := range []string{"approved", "denied"} {
				err := s.DecideApproval(ctx, a.ID, to, "mallory", "fresh", "fresh-tok", t0.Add(2*time.Minute), t0.Add(time.Hour))
				if !errors.Is(err, ErrConflict) {
					t.Errorf("%s -> %s: %v, want ErrConflict", st, to, err)
				}
			}
			after, err := s.ApprovalByID(ctx, a.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Errorf("row changed:\nbefore %+v\nafter  %+v", before, after)
			}
		})
	}
}

// Two people pressing approve at once on an access grant must not both
// become the first approver: exactly one wins, and only one partial event
// is written.
func TestMarkPartiallyApprovedIsSingleUseUnderConcurrency(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if err := s.CreateApproval(ctx, appr("a1")); err != nil {
		t.Fatal(err)
	}
	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, conflict := 0, 0
	var other []error
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := s.MarkPartiallyApproved(ctx, "a1", fmt.Sprintf("ap%d", i), fmt.Sprintf("p%d", i), t0.Add(time.Minute))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrConflict):
				conflict++
			default:
				other = append(other, err)
			}
		}(i)
	}
	wg.Wait()
	if ok != 1 || conflict != n-1 || len(other) != 0 {
		t.Errorf("ok=%d conflict=%d other=%v, want 1, %d, none", ok, conflict, n-1, other)
	}
	var events int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox WHERE kind = 'approval.partial'`).Scan(&events); err != nil || events != 1 {
		t.Errorf("approval.partial events = %d, %v; want 1", events, err)
	}
}

// The partial event names the first approver: an outbox reader sees both
// people of an access grant without reading the row back, and the other
// events keep their shape.
func TestPartialOutboxEventNamesTheFirstApprover(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if err := s.CreateApproval(ctx, appr("a1")); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkPartiallyApproved(ctx, "a1", "ap1", "bob", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	payloads := map[string]string{}
	rows, err := s.db.QueryContext(ctx, `SELECT kind, payload FROM outbox`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var k, p string
		if err := rows.Scan(&k, &p); err != nil {
			t.Fatal(err)
		}
		payloads[k] = p
	}
	if got, want := payloads["approval.partial"], `{"approval_id":"a1","status":"partially_approved","first_approver_name":"bob"}`; got != want {
		t.Errorf("partial payload = %s, want %s", got, want)
	}
	if got, want := payloads["approval.pending"], `{"approval_id":"a1","status":"pending"}`; got != want {
		t.Errorf("pending payload = %s, want %s", got, want)
	}
}

// A revoked first approver no longer counts (ruling E-R15a): the second
// approval's compare-and-swap refuses to release over them, and only a
// non-live first approver can be replaced -- never a live one.
func TestRevokedFirstApproverIsReplacedNeverReleased(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if err := s.CreateApproval(ctx, appr("a1")); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"ap1", "ap2", "ap3"} {
		if err := s.CreateApprover(ctx, Approver{ID: id, Name: "n-" + id, Created: t0}, []byte("h-"+id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MarkPartiallyApproved(ctx, "a1", "ap1", "bob", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if live, err := s.ApproverLive(ctx, "ap1"); err != nil || !live {
		t.Fatalf("ApproverLive(ap1) = %v, %v", live, err)
	}
	// A live first approver is never replaced.
	if err := s.ReplaceFirstApprover(ctx, "a1", "ap1", "ap2", "carol", t0.Add(2*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacing a live first approver: %v, want ErrConflict", err)
	}
	if err := s.RevokeApprover(ctx, "ap1", t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"ap1", "", "ghost"} {
		if live, err := s.ApproverLive(ctx, id); err != nil || live {
			t.Fatalf("ApproverLive(%q) = %v, %v, want false", id, live, err)
		}
	}
	if err := s.ApproveSecond(ctx, "a1", "ap1", "ap2", "carol", "n1", "tok", t0.Add(3*time.Minute), t0.Add(18*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("second approval over a revoked first approver: %v, want ErrConflict", err)
	}
	// Pinned to the first approver checked: a stale id does not replace.
	if err := s.ReplaceFirstApprover(ctx, "a1", "ap9", "ap2", "carol", t0.Add(3*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("replace pinned to the wrong first approver: %v, want ErrConflict", err)
	}
	if err := s.ReplaceFirstApprover(ctx, "a1", "ap1", "ap2", "carol", t0.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ApprovalByID(ctx, "a1")
	if got.Status != "partially_approved" || got.FirstApproverID != "ap2" || got.FirstApproverName != "carol" ||
		!got.FirstApproved.Equal(t0.Add(3*time.Minute)) || got.Token != "" || got.Nonce != "" {
		t.Fatalf("after replacement = %+v", got)
	}
	if err := s.ApproveSecond(ctx, "a1", "ap2", "ap3", "dave", "n1", "tok", t0.Add(4*time.Minute), t0.Add(19*time.Minute)); err != nil {
		t.Fatalf("second approval over the live replacement: %v", err)
	}
	// Deny still stands in both waiting states.
	b := appr("b1")
	b.RequestDigest = "b1"
	if err := s.CreateApproval(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkPartiallyApproved(ctx, "b1", "ap3", "erin", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.DecideApproval(ctx, "b1", "denied", "frank", "", "", t0.Add(2*time.Minute), t0.Add(time.Hour)); err != nil {
		t.Fatalf("deny of a partial: %v", err)
	}
	var kinds []string
	rows, err := s.db.QueryContext(ctx, `SELECT kind, payload FROM outbox ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var p []byte
		rows.Scan(&k, &p)
		if strings.Contains(string(p), `"approval_id":"a1"`) {
			kinds = append(kinds, k)
		}
	}
	if want := []string{"approval.pending", "approval.partial", "approval.partial", "approval.decided"}; !slices.Equal(kinds, want) {
		t.Errorf("outbox = %v, want %v", kinds, want)
	}
}
