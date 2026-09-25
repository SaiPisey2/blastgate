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

	_ "modernc.org/sqlite"
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
}

func Open(path string) (*Store, error) {
	// The path goes into a URI; a '?' or '#' in it would be read as the
	// start of the query and silently open a different file.
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("database path %q may not contain '?' or '#'", path)
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating %s: %w", path, err)
	}
	// Token hashes are not tokens, but the file is still nobody else's to read.
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return err
	}
	var v int
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&v); err != nil {
		return err
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (?)`, i+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
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
