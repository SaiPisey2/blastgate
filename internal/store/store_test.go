package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
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

// A first run can open the database from two processes at once -- `serve`
// started in the background and `session new` straight after. Without an
// immediate transaction around the migration, one of them failed with
// SQLITE_BUSY, or both tried to create the same table.
func TestConcurrentFirstOpenMigratesOnce(t *testing.T) {
	const openers = 8
	for round := 0; round < 10; round++ {
		p := filepath.Join(t.TempDir(), "blastgate.db")
		errs := make(chan error, openers)
		var start sync.WaitGroup
		start.Add(1)
		for i := 0; i < openers; i++ {
			go func() {
				start.Wait()
				s, err := Open(p)
				if err == nil {
					err = s.Close()
				}
				errs <- err
			}()
		}
		start.Done()
		for i := 0; i < openers; i++ {
			if err := <-errs; err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
		}
		s, err := Open(p)
		if err != nil {
			t.Fatal(err)
		}
		var rows, max int
		if err := s.db.QueryRow(`SELECT COUNT(*), MAX(version) FROM schema_version`).Scan(&rows, &max); err != nil {
			t.Fatal(err)
		}
		s.Close()
		if rows != len(migrations) || max != len(migrations) {
			t.Fatalf("round %d: schema_version has %d rows, max %d; want %d", round, rows, max, len(migrations))
		}
	}
}

// Token hashes are not tokens, but the database is nobody else's to read,
// and in WAL mode most recent writes live in -wal until a checkpoint.
// SQLite gives -wal and -shm the database file's mode, so a database
// created group-readable leaked through them even after it was chmodded.
func TestDatabaseFilesArePrivate(t *testing.T) {
	s, p := open(t)
	if err := s.CreateSession(context.Background(), Session{ID: "s1", Human: "a", Agent: "b", Created: t0, Expires: t0.Add(time.Hour)}, []byte("h")); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{p, p + "-wal", p + "-shm"} {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := fi.Mode().Perm(); m&0o077 != 0 {
			t.Errorf("%s has mode %v; want no group or world access", filepath.Base(f), m)
		}
	}
}

// The retry around the migration assumes every connection waits for a
// lock rather than failing at once; a DSN typo would silently drop that.
func TestConnectionsWaitForLocks(t *testing.T) {
	s, _ := open(t)
	var ms int
	if err := s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&ms); err != nil {
		t.Fatal(err)
	}
	if ms != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", ms)
	}
}

func TestSessionByIDAndListSessionsLimit(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	for i, id := range []string{"s1", "s2", "s3"} {
		if err := s.CreateSession(ctx, Session{ID: id, Human: "h", Agent: "x", Created: t0.Add(time.Duration(i) * time.Minute), Expires: t0.Add(time.Hour)}, []byte(id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RevokeSession(ctx, "s1", t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := s.SessionByID(ctx, "s1")
	if err != nil || got.ID != "s1" || got.Human != "h" || !got.Revoked.Equal(t0.Add(time.Second)) {
		t.Errorf("SessionByID = %+v, %v", got, err)
	}
	if _, err := s.SessionByID(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing session: %v", err)
	}
	l, err := s.ListSessionsLimit(ctx, 2)
	if err != nil || len(l) != 2 || l[0].ID != "s3" || l[1].ID != "s2" {
		t.Errorf("ListSessionsLimit(2) = %+v, %v", l, err)
	}
	if l, _ := s.ListSessionsLimit(ctx, 0); len(l) != 0 {
		t.Errorf("limit 0 is nothing, not unlimited: %d", len(l))
	}
}
