package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func row(kind string) AuditRow {
	return AuditRow{At: t0, Kind: kind, RequestID: "r1", Session: "s1", Human: "alice", Agent: "coding-agent",
		Source: "proxy", Verb: "delete", Resource: "pods", Namespace: "demo", Name: "web-1",
		RequestDigest: "d", Class: "REVERSIBLE", Measured: true, Rule: "safe", Decision: "allow", Status: 200}
}

func TestAuditAppendsAndReadsBackOldestFirst(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	a, b := row("decision"), row("result")
	b.At = t0.Add(time.Second)
	if err := s.AppendAudit(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendAudit(ctx, b); err != nil {
		t.Fatal(err)
	}
	got, err := s.AuditSince(ctx, t0.Add(-time.Hour), "")
	if err != nil || len(got) != 2 || got[0].Kind != "decision" || got[1].Kind != "result" || got[1].Status != 200 {
		t.Fatalf("got %+v, %v", got, err)
	}
	only, _ := s.AuditSince(ctx, t0.Add(-time.Hour), "result")
	if len(only) != 1 {
		t.Errorf("kind filter: %d rows", len(only))
	}
}

func TestAuditIsAppendOnly(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	s.AppendAudit(ctx, row("result"))
	if _, err := s.db.ExecContext(ctx, `UPDATE audit SET decision = 'allow'`); err == nil {
		t.Error("audit row was updated")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM audit`); err == nil {
		t.Error("audit row was deleted")
	}
}

func appr(id string) Approval {
	return Approval{ID: id, Session: "s1", Human: "alice", Agent: "coding-agent", RequestDigest: "rd", ImpactDigest: "id",
		ActionJSON: []byte(`{}`), ImpactJSON: []byte(`{}`), Rule: "data-destruction", Status: "pending",
		Created: t0, Expires: t0.Add(time.Hour)}
}

func TestApprovalLifecycle(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if err := s.CreateApproval(ctx, appr("a1")); err != nil {
		t.Fatal(err)
	}
	if err := s.DecideApproval(ctx, "a1", "approved", "bob", "n1", "tok", t0.Add(time.Minute), t0.Add(16*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.DecideApproval(ctx, "a1", "denied", "carol", "", "", t0, t0); !errors.Is(err, ErrConflict) {
		t.Errorf("second decision: %v", err)
	}
	got, _ := s.ApprovalByID(ctx, "a1")
	if got.Status != "approved" || got.DecidedBy != "bob" || got.Nonce != "n1" || got.Token != "tok" {
		t.Errorf("approval = %+v", got)
	}
	if err := s.ConsumeApproval(ctx, "a1", "n1", t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeApproval(ctx, "a1", "n1", t0.Add(3*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Errorf("second consume: %v", err)
	}
	var events int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox`).Scan(&events)
	if events != 2 {
		t.Errorf("outbox events = %d, want pending + decided", events)
	}
}

func TestConsumeIsSingleUseUnderConcurrency(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	s.CreateApproval(ctx, appr("a1"))
	s.DecideApproval(ctx, "a1", "approved", "bob", "n1", "tok", t0, t0.Add(time.Hour))
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.ConsumeApproval(ctx, "a1", "n1", t0) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Errorf("%d concurrent consumes succeeded, want exactly 1", ok)
	}
}

func TestLatestApprovalIsNewest(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	a, b := appr("old"), appr("new")
	b.Created = t0.Add(time.Minute)
	s.CreateApproval(ctx, a)
	s.CreateApproval(ctx, b)
	got, err := s.LatestApproval(ctx, "s1", "rd")
	if err != nil || got.ID != "new" {
		t.Errorf("latest = %+v, %v", got, err)
	}
	if _, err := s.LatestApproval(ctx, "s1", "other"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
}

func TestSetApprovalStatusGuardsTheFromState(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	s.CreateApproval(ctx, appr("a1"))
	if err := s.SetApprovalStatus(ctx, "a1", "approved", "superseded"); !errors.Is(err, ErrConflict) {
		t.Errorf("transition from the wrong state: %v", err)
	}
	if err := s.SetApprovalStatus(ctx, "a1", "pending", "expired"); err != nil {
		t.Error(err)
	}
}
