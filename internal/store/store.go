// Package store is blastgate's system of record, on SQLite so a first run
// needs nothing installed. Migrations are append-only: an entry, once
// released, is never edited, because a database created by an earlier
// build has already run it.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var ErrNotFound = errors.New("not found")

type Store struct{ db *sql.DB }

type Session struct {
	ID, Human, Agent string
	Created, Expires time.Time
	Revoked          time.Time
}

var migrations = []string{
	`CREATE TABLE sessions (
		id         TEXT PRIMARY KEY,
		token_hash BLOB NOT NULL UNIQUE,
		human      TEXT NOT NULL,
		agent      TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		revoked_at INTEGER
	)`,
	`CREATE TABLE audit (
		id             INTEGER PRIMARY KEY AUTOINCREMENT,
		at             INTEGER NOT NULL,
		kind           TEXT NOT NULL CHECK (kind IN ('decision','result')),
		request_id     TEXT NOT NULL,
		session_id     TEXT NOT NULL,
		human          TEXT NOT NULL,
		agent          TEXT NOT NULL,
		source         TEXT NOT NULL,
		verb           TEXT NOT NULL,
		grp            TEXT NOT NULL,
		resource       TEXT NOT NULL,
		subresource    TEXT NOT NULL,
		namespace      TEXT NOT NULL,
		name           TEXT NOT NULL,
		request_digest TEXT NOT NULL,
		action_json    BLOB,
		impact_json    BLOB,
		labels_json    BLOB,
		class          TEXT NOT NULL,
		measured       INTEGER NOT NULL,
		rule           TEXT NOT NULL,
		decision       TEXT NOT NULL,
		approval_id    TEXT NOT NULL,
		status         INTEGER NOT NULL,
		outcome        TEXT NOT NULL,
		latency_ms     INTEGER NOT NULL,
		snapshot       TEXT NOT NULL
	);
	CREATE INDEX audit_at ON audit(at);
	CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
	CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;`,
	`CREATE TABLE approvals (
		id             TEXT PRIMARY KEY,
		session_id     TEXT NOT NULL,
		human          TEXT NOT NULL,
		agent          TEXT NOT NULL,
		request_digest TEXT NOT NULL,
		impact_digest  TEXT NOT NULL,
		action_json    BLOB NOT NULL,
		impact_json    BLOB NOT NULL,
		rule           TEXT NOT NULL,
		status         TEXT NOT NULL,
		created_at     INTEGER NOT NULL,
		decided_at     INTEGER,
		decided_by     TEXT NOT NULL DEFAULT '',
		nonce          TEXT NOT NULL DEFAULT '',
		token          TEXT NOT NULL DEFAULT '',
		expires_at     INTEGER NOT NULL
	);
	CREATE INDEX approvals_lookup ON approvals(session_id, request_digest, created_at);
	CREATE TABLE nonces (nonce TEXT PRIMARY KEY, used_at INTEGER NOT NULL);
	CREATE TABLE outbox (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		kind         TEXT NOT NULL,
		payload      BLOB NOT NULL,
		created_at   INTEGER NOT NULL,
		delivered_at INTEGER
	);`,
}

func Open(path string) (*Store, error) {
	// The path goes into a URI; a '?' or '#' in it would be read as the
	// start of the query and silently open a different file.
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("database path %q may not contain '?' or '#'", path)
	}
	// Token hashes are not tokens, but the file is still nobody else's to
	// read. It is created private before SQLite opens it because SQLite
	// gives the -wal and -shm files the database's mode: a database left
	// to the umask and chmodded afterwards kept group-readable -wal and
	// -shm files, and in WAL mode recent writes live in -wal.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	// busy_timeout comes first so it already applies to the journal_mode
	// switch, which needs a lock. _txlock=immediate takes the write lock
	// at BEGIN: a deferred transaction that reads and then writes gets
	// SQLITE_BUSY at once in WAL mode, without waiting at all.
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating %s: %w", path, err)
	}
	// An older build created the database with the umask's mode, and its
	// -wal and -shm with it; they are only recreated once every connection
	// closes, so they are corrected here too.
	for _, p := range []string{path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			db.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// migrateAttempts bounds the retry around a migration that found the
// database busy. busy_timeout already waits up to 5s for a lock; the retry
// covers the moments it does not apply, such as two processes switching a
// brand-new file to WAL at once.
const migrateAttempts = 10

func (s *Store) migrate(ctx context.Context) error {
	var err error
	for i := 0; i < migrateAttempts; i++ {
		if err = s.migrateOnce(ctx); err == nil || !isBusy(err) {
			return err
		}
		time.Sleep(time.Duration(i+1) * 20 * time.Millisecond)
	}
	return err
}

// migrateOnce runs every pending migration in one immediate transaction.
// The schema version is read inside it, after the write lock is held: on a
// first run `serve` and `session new` can open the database together, and
// a version read before the lock let both apply migration 1.
func (s *Store) migrateOnce(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return err
	}
	var v int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&v); err != nil {
		return err
	}
	for i := v; i < len(migrations); i++ {
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (?)`, i+1); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func isBusy(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code()&0xff == sqlite3.SQLITE_BUSY
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.UnixMilli(v.Int64).UTC()
}

func (s *Store) CreateSession(ctx context.Context, sess Session, tokenHash []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, token_hash, human, agent, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		sess.ID, tokenHash, sess.Human, sess.Agent, ms(sess.Created), ms(sess.Expires))
	return err
}

const sessionCols = `id, human, agent, created_at, expires_at, revoked_at`

func scanSession(row interface{ Scan(...any) error }) (Session, error) {
	var s Session
	var created, expires, revoked sql.NullInt64
	if err := row.Scan(&s.ID, &s.Human, &s.Agent, &created, &expires, &revoked); err != nil {
		return Session{}, err
	}
	s.Created, s.Expires, s.Revoked = fromMS(created), fromMS(expires), fromMS(revoked)
	return s, nil
}

func (s *Store) SessionByTokenHash(ctx context.Context, h []byte) (Session, error) {
	sess, err := scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE token_hash = ?`, h))
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return sess, err
}

func (s *Store) ListSessions(ctx context.Context) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+sessionCols+` FROM sessions ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// RevokeSession keeps the first revocation time: a second revoke is a
// no-op, not a rewrite of when access actually ended.
func (s *Store) RevokeSession(ctx context.Context, id string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, ms(at), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	var one int
	err = s.db.QueryRowContext(ctx, `SELECT 1 FROM sessions WHERE id = ?`, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
