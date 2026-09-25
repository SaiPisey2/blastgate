package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Approver is a human allowed to decide holds through the CLI-issued
// bga_ token: `blastgate approver new` prints the token once and stores
// only its hash, exactly like a session's token.
type Approver struct {
	ID, Name         string
	Created, Revoked time.Time
}

const approverCols = `id, name, created_at, revoked_at`
const approverInsertCols = `id, name, token_hash, created_at, revoked_at`

func scanApprover(row interface{ Scan(...any) error }) (Approver, error) {
	var a Approver
	var created int64
	var revoked sql.NullInt64
	if err := row.Scan(&a.ID, &a.Name, &created, &revoked); err != nil {
		return Approver{}, err
	}
	a.Created = time.UnixMilli(created).UTC()
	a.Revoked = fromMS(revoked)
	return a, nil
}

// CreateApprover inserts a new approver. The partial unique index on
// (name) WHERE revoked_at IS NULL is the actual guard against two live
// approvers sharing a name; a revoked approver's name is free to reuse
// because it can no longer decide anything under it. A collision on that
// index, or on the token hash, comes back as ErrConflict rather than a
// raw driver error, matching how the rest of the store reports a losing
// compare-and-swap.
func (s *Store) CreateApprover(ctx context.Context, a Approver, tokenHash []byte) error {
	var revoked sql.NullInt64
	if !a.Revoked.IsZero() {
		revoked = sql.NullInt64{Int64: ms(a.Revoked), Valid: true}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO approvers (`+approverInsertCols+`) VALUES (?, ?, ?, ?, ?)`,
		a.ID, a.Name, tokenHash, ms(a.Created), revoked)
	if isConstraint(err) {
		return ErrConflict
	}
	return err
}

func (s *Store) ApproverByTokenHash(ctx context.Context, h []byte) (Approver, error) {
	a, err := scanApprover(s.db.QueryRowContext(ctx, `SELECT `+approverCols+` FROM approvers WHERE token_hash = ?`, h))
	if errors.Is(err, sql.ErrNoRows) {
		return Approver{}, ErrNotFound
	}
	return a, err
}

// ListApprovers returns every approver, newest first, live and revoked
// alike: an operator revoking access needs to see who is still live, and
// an audit of who ever held it needs the revoked ones too.
func (s *Store) ListApprovers(ctx context.Context) ([]Approver, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+approverCols+` FROM approvers ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approver
	for rows.Next() {
		a, err := scanApprover(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RevokeApprover revokes the approver and, in the same transaction, every
// one of their still-live UI sessions: a revoked approver whose browser
// cookie kept working until it happened to expire would defeat the point
// of revoking them at all. Idempotent like RevokeSession: a second revoke
// keeps the first revocation time and still re-checks (harmlessly) for
// sessions created since.
func (s *Store) RevokeApprover(ctx context.Context, id string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE approvers SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, ms(at), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM approvers WHERE id = ?`, id).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ui_sessions SET revoked_at = ? WHERE approver_id = ? AND revoked_at IS NULL`, ms(at), id); err != nil {
		return err
	}
	return tx.Commit()
}

// UISession is a browser login: the cookie value is never stored, only
// its hash (id_hash), the same way an approver's token is never stored.
// There is no separate visible ID, unlike Session — a UI session is
// revoked by the hash the browser itself proves it holds (logout) or by
// revoking the approver, never by a public identifier.
type UISession struct {
	ID                             string
	ApproverID, ApproverName, CSRF string
	Created, Expires, Revoked      time.Time
	// ApproverRevoked is the approver's own revocation time, read by
	// UISessionByHash. RevokeApprover sweeps the approver's sessions, but
	// a login that read the approver as live just before that sweep and
	// inserted its session just after leaves a live row under a revoked
	// approver; only checking this field as well closes that gap.
	ApproverRevoked time.Time
}

// CreateUISession inserts a new browser session under an approver. u.ID
// is not persisted: the table has no plain identifier column, only the
// hash, so there is nothing to write it into.
func (s *Store) CreateUISession(ctx context.Context, u UISession, idHash []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ui_sessions (id_hash, approver_id, csrf, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		idHash, u.ApproverID, u.CSRF, ms(u.Created), ms(u.Expires))
	return err
}

// UISessionByHash looks a session up by its cookie hash and joins the
// approver's current name and revocation time, so a caller rendering
// "signed in as alice", or refusing a revoked approver, never has to make
// a second query. Like SessionByTokenHash, it returns a
// revoked row rather than hiding it: the caller (session middleware)
// decides what a non-zero Revoked means.
func (s *Store) UISessionByHash(ctx context.Context, h []byte) (UISession, error) {
	var u UISession
	var created, expires int64
	var revoked, approverRevoked sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT ui_sessions.approver_id, approvers.name, ui_sessions.csrf, ui_sessions.created_at, ui_sessions.expires_at, ui_sessions.revoked_at, approvers.revoked_at
		 FROM ui_sessions JOIN approvers ON approvers.id = ui_sessions.approver_id
		 WHERE ui_sessions.id_hash = ?`, h).
		Scan(&u.ApproverID, &u.ApproverName, &u.CSRF, &created, &expires, &revoked, &approverRevoked)
	if errors.Is(err, sql.ErrNoRows) {
		return UISession{}, ErrNotFound
	}
	if err != nil {
		return UISession{}, err
	}
	u.Created = time.UnixMilli(created).UTC()
	u.Expires = time.UnixMilli(expires).UTC()
	u.Revoked = fromMS(revoked)
	u.ApproverRevoked = fromMS(approverRevoked)
	return u, nil
}

// RevokeUISession is the logout path: it keeps the first revocation time,
// exactly like RevokeSession, so a replayed logout can't push the
// recorded end of access later than it really was.
func (s *Store) RevokeUISession(ctx context.Context, idHash []byte, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE ui_sessions SET revoked_at = ? WHERE id_hash = ? AND revoked_at IS NULL`, ms(at), idHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	var one int
	err = s.db.QueryRowContext(ctx, `SELECT 1 FROM ui_sessions WHERE id_hash = ?`, idHash).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// AuditFilter narrows AuditPage's result. A zero field means "don't
// filter on this"; BeforeID <= 0 means "start from the newest row".
type AuditFilter struct {
	BeforeID                            int64
	Limit                               int
	Agent, Human, Class, Decision, Kind string
}

// clampAuditLimit keeps a page request from becoming an unbounded scan
// (a caller-supplied Limit of 0 would otherwise mean "no rows" under
// SQL's own LIMIT semantics, not "give me a default") or from asking
// SQLite to hand back the whole table at once.
func clampAuditLimit(n int) int {
	switch {
	case n <= 0:
		return 1
	case n > 500:
		return 500
	default:
		return n
	}
}

// AuditPage returns audit rows newest-first by id, the shape the admin
// UI's log view pages backwards through: the first call omits BeforeID,
// every later call passes the last row's ID to continue past it.
func (s *Store) AuditPage(ctx context.Context, f AuditFilter) ([]AuditRow, error) {
	q := `SELECT ` + auditSelectCols + ` FROM audit WHERE 1 = 1`
	var args []any
	if f.BeforeID > 0 {
		q += ` AND id < ?`
		args = append(args, f.BeforeID)
	}
	if f.Agent != "" {
		q += ` AND agent = ?`
		args = append(args, f.Agent)
	}
	if f.Human != "" {
		q += ` AND human = ?`
		args = append(args, f.Human)
	}
	if f.Class != "" {
		q += ` AND class = ?`
		args = append(args, f.Class)
	}
	if f.Decision != "" {
		q += ` AND decision = ?`
		args = append(args, f.Decision)
	}
	if f.Kind != "" {
		q += ` AND kind = ?`
		args = append(args, f.Kind)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, clampAuditLimit(f.Limit))
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		r, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AuditAfter returns rows with id > afterID, oldest first: the live
// stream tails the table by remembering the last id it saw and asking
// for everything since, the mirror image of AuditPage's backward paging.
func (s *Store) AuditAfter(ctx context.Context, afterID int64, limit int) ([]AuditRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+auditSelectCols+` FROM audit WHERE id > ? ORDER BY id ASC LIMIT ?`, afterID, clampAuditLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		r, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
