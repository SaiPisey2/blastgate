package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestApproverNamesAreUniqueWhileLive(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if err := s.CreateApprover(ctx, Approver{ID: "a1", Name: "alice", Created: t0}, []byte("h1")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateApprover(ctx, Approver{ID: "a2", Name: "alice", Created: t0.Add(time.Minute)}, []byte("h2")); err == nil {
		t.Error("a second live approver named alice was accepted")
	}
	if err := s.RevokeApprover(ctx, "a1", t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateApprover(ctx, Approver{ID: "a3", Name: "alice", Created: t0.Add(3 * time.Minute)}, []byte("h3")); err != nil {
		t.Errorf("alice after revoke: %v", err)
	}
}

func TestRevokingAnApproverRevokesItsSessions(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if err := s.CreateApprover(ctx, Approver{ID: "a1", Name: "alice", Created: t0}, []byte("tok")); err != nil {
		t.Fatal(err)
	}
	u := UISession{ApproverID: "a1", CSRF: "csrf1", Created: t0, Expires: t0.Add(12 * time.Hour)}
	if err := s.CreateUISession(ctx, u, []byte("sh1")); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(time.Minute)
	if err := s.RevokeApprover(ctx, "a1", at); err != nil {
		t.Fatal(err)
	}
	got, err := s.UISessionByHash(ctx, []byte("sh1"))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Revoked.Equal(at) {
		t.Errorf("session revoked = %v, want %v", got.Revoked, at)
	}
	if !got.ApproverRevoked.Equal(at) {
		t.Errorf("approver revoked = %v, want %v", got.ApproverRevoked, at)
	}
	if err := s.RevokeApprover(ctx, "ghost", at); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking a missing approver: %v", err)
	}
}

func TestUISessionJoinsApproverName(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if err := s.CreateApprover(ctx, Approver{ID: "a1", Name: "alice", Created: t0}, []byte("tok")); err != nil {
		t.Fatal(err)
	}
	u := UISession{ApproverID: "a1", CSRF: "csrf1", Created: t0, Expires: t0.Add(12 * time.Hour)}
	if err := s.CreateUISession(ctx, u, []byte("sh1")); err != nil {
		t.Fatal(err)
	}
	got, err := s.UISessionByHash(ctx, []byte("sh1"))
	if err != nil {
		t.Fatal(err)
	}
	if got.ApproverID != "a1" || got.ApproverName != "alice" || got.CSRF != "csrf1" || !got.Expires.Equal(u.Expires) || !got.Revoked.IsZero() || !got.ApproverRevoked.IsZero() {
		t.Errorf("got %+v", got)
	}
	if err := s.RevokeUISession(ctx, []byte("sh1"), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got2, err := s.UISessionByHash(ctx, []byte("sh1"))
	if err != nil {
		t.Fatal(err)
	}
	if !got2.Revoked.Equal(t0.Add(time.Hour)) {
		t.Errorf("revoked = %v, want %v", got2.Revoked, t0.Add(time.Hour))
	}
	if _, err := s.UISessionByHash(ctx, []byte("nope")); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown hash: %v", err)
	}
	if err := s.RevokeUISession(ctx, []byte("nope"), t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking an unknown hash: %v", err)
	}
}

func bypassRow(name string) BypassRow {
	return BypassRow{At: t0, User: "system:serviceaccount:default:controller", Groups: []string{"system:serviceaccounts"},
		Verb: "delete", Resource: "pods", Namespace: "demo", Name: name, UID: "u-" + name}
}

func TestBypassIsAppendOnly(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	a, b := bypassRow("web-1"), bypassRow("web-2")
	b.At = t0.Add(time.Minute)
	if err := s.AppendBypass(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendBypass(ctx, b); err != nil {
		t.Fatal(err)
	}
	got, err := s.BypassSince(ctx, t0.Add(-time.Hour), 10)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got[0].Name != "web-2" || got[1].Name != "web-1" {
		t.Errorf("not newest first: %+v", got)
	}
	if len(got[0].Groups) != 1 || got[0].Groups[0] != "system:serviceaccounts" {
		t.Errorf("groups round-trip: %+v", got[0].Groups)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE bypass SET user = 'x'`); err == nil {
		t.Error("a bypass row was updated")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM bypass`); err == nil {
		t.Error("a bypass row was deleted")
	}
}

func TestAuditPageFiltersAndPagesNewestFirst(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	agents := []string{"coding-agent", "other-agent"}
	classes := []string{"REVERSIBLE", "IRREVERSIBLE"}
	decisions := []string{"allow", "hold"}
	wantOther, wantIrrev, wantHold := 0, 0, 0
	for i := 0; i < 7; i++ {
		r := row("decision")
		r.At = t0.Add(time.Duration(i) * time.Second)
		r.Agent = agents[i%2]
		r.Class = classes[i%2]
		r.Decision = decisions[i%2]
		if err := s.AppendAudit(ctx, r); err != nil {
			t.Fatal(err)
		}
		if r.Agent == "other-agent" {
			wantOther++
		}
		if r.Class == "IRREVERSIBLE" {
			wantIrrev++
		}
		if r.Decision == "hold" {
			wantHold++
		}
	}

	page1, err := s.AuditPage(ctx, AuditFilter{Limit: 3})
	if err != nil || len(page1) != 3 {
		t.Fatalf("page1 = %+v, %v", page1, err)
	}
	for i := 1; i < len(page1); i++ {
		if page1[i-1].ID <= page1[i].ID {
			t.Fatalf("page1 not newest first: %+v", page1)
		}
	}
	page2, err := s.AuditPage(ctx, AuditFilter{Limit: 3, BeforeID: page1[len(page1)-1].ID})
	if err != nil || len(page2) != 3 {
		t.Fatalf("page2 = %+v, %v", page2, err)
	}
	if page2[0].ID >= page1[len(page1)-1].ID {
		t.Errorf("page2 overlaps page1: last of page1 = %d, first of page2 = %d", page1[len(page1)-1].ID, page2[0].ID)
	}

	onlyOther, err := s.AuditPage(ctx, AuditFilter{Limit: 500, Agent: "other-agent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(onlyOther) != wantOther {
		t.Errorf("agent filter = %d rows, want %d", len(onlyOther), wantOther)
	}
	for _, r := range onlyOther {
		if r.Agent != "other-agent" {
			t.Errorf("agent filter leaked %+v", r)
		}
	}

	onlyIrrev, err := s.AuditPage(ctx, AuditFilter{Limit: 500, Class: "IRREVERSIBLE"})
	if err != nil {
		t.Fatal(err)
	}
	if len(onlyIrrev) != wantIrrev {
		t.Errorf("class filter = %d rows, want %d", len(onlyIrrev), wantIrrev)
	}

	onlyHold, err := s.AuditPage(ctx, AuditFilter{Limit: 500, Decision: "hold"})
	if err != nil {
		t.Fatal(err)
	}
	if len(onlyHold) != wantHold {
		t.Errorf("decision filter = %d rows, want %d", len(onlyHold), wantHold)
	}

	zero, err := s.AuditPage(ctx, AuditFilter{Limit: 0})
	if err != nil || len(zero) != 1 {
		t.Errorf("Limit 0 = %d rows, %v; want 1", len(zero), err)
	}

	// Push the table past 500 rows so a huge Limit proves the clamp
	// rather than just returning everything there happens to be.
	for i := 0; i < 500; i++ {
		r := row("decision")
		r.At = t0.Add(time.Hour)
		r.Agent = "bulk-agent"
		if err := s.AppendAudit(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	huge, err := s.AuditPage(ctx, AuditFilter{Limit: 10000})
	if err != nil || len(huge) != 500 {
		t.Errorf("Limit 10000 = %d rows, %v; want 500 (clamped)", len(huge), err)
	}
}

func TestAuditAfterIsOldestFirst(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		r := row("decision")
		r.At = t0.Add(time.Duration(i) * time.Second)
		r.Name = "obj"
		if err := s.AppendAudit(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	seeded, err := s.AuditPage(ctx, AuditFilter{Limit: 500})
	if err != nil || len(seeded) != 3 {
		t.Fatalf("seed check: %+v, %v", seeded, err)
	}
	oldestID := seeded[len(seeded)-1].ID

	got, err := s.AuditAfter(ctx, oldestID-1, 10)
	if err != nil || len(got) != 3 {
		t.Fatalf("got %+v, %v", got, err)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].ID >= got[i].ID {
			t.Fatalf("not oldest first: %+v", got)
		}
	}
	got2, err := s.AuditAfter(ctx, got[0].ID, 10)
	if err != nil || len(got2) != 2 {
		t.Errorf("after excludes the row it started from: got %+v, %v", got2, err)
	}
}

func TestAuditSinceLimitKeepsTheNewest(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		r := row("decision")
		r.At = t0.Add(time.Duration(i) * time.Second)
		r.RequestID = string(rune('a' + i))
		if i == 2 {
			r.Kind = "result"
		}
		if err := s.AppendAudit(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	// Decisions at or after t0+1s are b, d and e; the newest two are d
	// and e, returned oldest first.
	got, err := s.AuditSinceLimit(ctx, t0.Add(time.Second), "decision", 2)
	if err != nil || len(got) != 2 || got[0].RequestID != "d" || got[1].RequestID != "e" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got, _ := s.AuditSinceLimit(ctx, t0, "", 100); len(got) != 5 {
		t.Errorf("a limit past the rows returns them all: %d", len(got))
	}
	if got, _ := s.AuditSinceLimit(ctx, t0, "", 0); len(got) != 0 {
		t.Errorf("limit 0 is nothing, not unlimited: %d", len(got))
	}
}

func TestListApprovalsLimitKeepsTheNewest(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	for i, id := range []string{"a1", "a2", "a3"} {
		a := appr(id)
		a.Created = t0.Add(time.Duration(i) * time.Second)
		if err := s.CreateApproval(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListApprovalsLimit(ctx, "", 2)
	if err != nil || len(got) != 2 || got[0].ID != "a3" || got[1].ID != "a2" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got, _ := s.ListApprovalsLimit(ctx, "pending", 0); len(got) != 0 {
		t.Errorf("limit 0 is nothing, not unlimited: %d", len(got))
	}
}
