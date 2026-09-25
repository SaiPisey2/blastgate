package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "blastgate.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, p
}

var t0 = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func TestCreateAndLookUpByHash(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	in := Session{ID: "s1", Human: "alice", Agent: "coding-agent", Created: t0, Expires: t0.Add(time.Hour)}
	if err := s.CreateSession(ctx, in, []byte("hash-1")); err != nil {
		t.Fatal(err)
	}
	got, err := s.SessionByTokenHash(ctx, []byte("hash-1"))
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "s1" || got.Human != "alice" || got.Agent != "coding-agent" || !got.Expires.Equal(in.Expires) || !got.Revoked.IsZero() {
		t.Errorf("got %+v", got)
	}
}

func TestUnknownHashIsNotFound(t *testing.T) {
	s, _ := open(t)
	if _, err := s.SessionByTokenHash(context.Background(), []byte("nope")); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestDuplicateHashIsRefused(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	a := Session{ID: "a", Human: "h", Agent: "x", Created: t0, Expires: t0.Add(time.Hour)}
	b := a
	b.ID = "b"
	if err := s.CreateSession(ctx, a, []byte("same")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, b, []byte("same")); err == nil {
		t.Error("two sessions share one token hash")
	}
}

func TestRevokeIsRecordedAndIdempotent(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	s.CreateSession(ctx, Session{ID: "s1", Human: "h", Agent: "x", Created: t0, Expires: t0.Add(time.Hour)}, []byte("h1"))
	if err := s.RevokeSession(ctx, "s1", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession(ctx, "s1", t0.Add(2*time.Minute)); err != nil {
		t.Errorf("second revoke: %v", err)
	}
	got, _ := s.SessionByTokenHash(ctx, []byte("h1"))
	if !got.Revoked.Equal(t0.Add(time.Minute)) {
		t.Errorf("revoked = %v, want the first revocation time", got.Revoked)
	}
	if err := s.RevokeSession(ctx, "ghost", t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking a missing session: %v", err)
	}
}

func TestListIsNewestFirst(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	s.CreateSession(ctx, Session{ID: "old", Human: "h", Agent: "x", Created: t0, Expires: t0.Add(time.Hour)}, []byte("1"))
	s.CreateSession(ctx, Session{ID: "new", Human: "h", Agent: "x", Created: t0.Add(time.Minute), Expires: t0.Add(time.Hour)}, []byte("2"))
	l, err := s.ListSessions(ctx)
	if err != nil || len(l) != 2 || l[0].ID != "new" {
		t.Errorf("list = %+v, err = %v", l, err)
	}
}

func TestReopenKeepsDataAndMigratesOnce(t *testing.T) {
	s, p := open(t)
	ctx := context.Background()
	s.CreateSession(ctx, Session{ID: "s1", Human: "h", Agent: "x", Created: t0, Expires: t0.Add(time.Hour)}, []byte("h1"))
	s.Close()
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.SessionByTokenHash(ctx, []byte("h1")); err != nil {
		t.Errorf("after reopen: %v", err)
	}
}
