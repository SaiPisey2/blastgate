package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// ErrConflict is returned when a caller's compare-and-swap on an
// approval's status (or a nonce's first use) loses: the row was not in
// the state the caller expected, because another request already moved
// it. Callers treat it as "ask again", never as a transient error to retry
// blindly — retrying a ConsumeApproval that lost is exactly the double
// spend the nonce exists to prevent.
var ErrConflict = errors.New("approval state changed")

// Approval is one hold on a mutating request: created pending, moved to
// approved or denied by a human, and — if approved — consumed exactly
// once when the held request is retried. superseded/expired are terminal
// states reached without ever being consumed.
type Approval struct {
	ID            string
	Session       string
	Human         string
	Agent         string
	RequestDigest string
	ImpactDigest  string
	ActionJSON    []byte
	ImpactJSON    []byte
	Rule          string
	Status        string // pending | approved | denied | consumed | superseded | expired
	Created       time.Time
	Decided       time.Time
	Expires       time.Time
	DecidedBy     string
	Nonce         string
	Token         string
}

const approvalCols = `id, session_id, human, agent, request_digest, impact_digest,
	action_json, impact_json, rule, status, created_at, decided_at, decided_by, nonce, token, expires_at`

func scanApproval(row interface{ Scan(...any) error }) (Approval, error) {
	var a Approval
	var created, expires int64
	var decided sql.NullInt64
	if err := row.Scan(&a.ID, &a.Session, &a.Human, &a.Agent, &a.RequestDigest, &a.ImpactDigest,
		&a.ActionJSON, &a.ImpactJSON, &a.Rule, &a.Status, &created, &decided, &a.DecidedBy, &a.Nonce, &a.Token, &expires); err != nil {
		return Approval{}, err
	}
	a.Created = time.UnixMilli(created).UTC()
	a.Expires = time.UnixMilli(expires).UTC()
	if decided.Valid {
		a.Decided = time.UnixMilli(decided.Int64).UTC()
	}
	return a, nil
}

// outboxEvent is the payload shape for both "approval.pending" and
// "approval.decided": small enough to read at a glance in the outbox
// table, and carrying only what a subscriber needs to go look the
// approval up itself rather than trusting a stale copy of its fields.
type outboxEvent struct {
	ApprovalID string `json:"approval_id"`
	Status     string `json:"status"`
}

func insertOutbox(ctx context.Context, tx *sql.Tx, kind, approvalID, status string, at time.Time) error {
	payload, err := json.Marshal(outboxEvent{ApprovalID: approvalID, Status: status})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO outbox (kind, payload, created_at) VALUES (?, ?, ?)`, kind, payload, ms(at))
	return err
}

// CreateApproval inserts the pending approval and its "approval.pending"
// outbox event in one transaction: a reader of the outbox must never see
// an event for an approval it cannot yet also find by ID.
func (s *Store) CreateApproval(ctx context.Context, a Approval) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var decided sql.NullInt64
	if !a.Decided.IsZero() {
		decided = sql.NullInt64{Int64: ms(a.Decided), Valid: true}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO approvals (`+approvalCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Session, a.Human, a.Agent, a.RequestDigest, a.ImpactDigest,
		a.ActionJSON, a.ImpactJSON, a.Rule, a.Status, ms(a.Created), decided, a.DecidedBy, a.Nonce, a.Token, ms(a.Expires)); err != nil {
		return err
	}
	if err := insertOutbox(ctx, tx, "approval.pending", a.ID, a.Status, a.Created); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ApprovalByID(ctx context.Context, id string) (Approval, error) {
	a, err := scanApproval(s.db.QueryRowContext(ctx, `SELECT `+approvalCols+` FROM approvals WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Approval{}, ErrNotFound
	}
	return a, err
}

// LatestApproval finds the newest approval for a session+request pair, so
// a retried request that already holds an approval (however it was later
// resolved) is matched to that one rather than starting a new hold.
func (s *Store) LatestApproval(ctx context.Context, session, requestDigest string) (Approval, error) {
	a, err := scanApproval(s.db.QueryRowContext(ctx,
		`SELECT `+approvalCols+` FROM approvals WHERE session_id = ? AND request_digest = ? ORDER BY created_at DESC, id DESC LIMIT 1`,
		session, requestDigest))
	if errors.Is(err, sql.ErrNoRows) {
		return Approval{}, ErrNotFound
	}
	return a, err
}

// ListApprovals returns approvals newest first; status == "" returns
// every status, for the operator-facing "what's pending / what happened"
// views.
func (s *Store) ListApprovals(ctx context.Context, status string) ([]Approval, error) {
	return s.listApprovals(ctx, status, 0)
}

// ListApprovalsLimit is ListApprovals stopping after the newest limit
// rows: the admin API serves this list per request, and the table only
// grows. A limit below 1 returns nothing rather than meaning "no limit".
func (s *Store) ListApprovalsLimit(ctx context.Context, status string, limit int) ([]Approval, error) {
	if limit < 1 {
		return nil, nil
	}
	return s.listApprovals(ctx, status, limit)
}

// ListPendingApprovals is the approver queue: pending approvals that can
// still be decided at now, oldest first, at most limit of them. Oldest
// first because the oldest is the one about to expire, and a limit that
// kept the newest would drop exactly that one. A pending row past its
// expiry is left out: Approve refuses it, and nothing moves it to expired
// until the agent retries, which it usually never does, so listing it
// would keep a card nobody can act on in the queue for good. Expired
// means now after expires_at, as approval.Service reads it.
func (s *Store) ListPendingApprovals(ctx context.Context, now time.Time, limit int) ([]Approval, error) {
	if limit < 1 {
		return nil, nil
	}
	return s.queryApprovals(ctx, `SELECT `+approvalCols+` FROM approvals WHERE status = 'pending' AND expires_at >= ?
		ORDER BY created_at ASC, id ASC LIMIT ?`, ms(now), limit)
}

func (s *Store) listApprovals(ctx context.Context, status string, limit int) ([]Approval, error) {
	q := `SELECT ` + approvalCols + ` FROM approvals`
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY created_at DESC, id DESC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	return s.queryApprovals(ctx, q, args...)
}

func (s *Store) queryApprovals(ctx context.Context, q string, args ...any) ([]Approval, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DecideApproval moves a pending approval to approved or denied. The
// WHERE clause is the compare-and-swap: two humans racing to decide the
// same approval must not both succeed, so only the first UPDATE that
// still finds status='pending' takes effect and the second gets
// ErrConflict instead of silently overwriting the first decision.
func (s *Store) DecideApproval(ctx context.Context, id, status, by, nonce, token string, decided, expires time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, nonce = ?, token = ?, expires_at = ? WHERE id = ? AND status = 'pending'`,
		status, ms(decided), by, nonce, token, ms(expires), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	if err := insertOutbox(ctx, tx, "approval.decided", id, status, decided); err != nil {
		return err
	}
	return tx.Commit()
}

// ConsumeApproval marks an approved hold consumed and burns its nonce in
// the same transaction: the UPDATE's WHERE clause is the single gate
// (status must still be 'approved' and the nonce must match), and the
// nonce INSERT's primary key is the second, independent gate — even if
// two callers both raced past a status check, only one can win the
// nonces primary key. Either loss returns ErrConflict, never a partial
// state where one row moved and the other did not.
func (s *Store) ConsumeApproval(ctx context.Context, id, nonce string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`UPDATE approvals SET status = 'consumed' WHERE id = ? AND status = 'approved' AND nonce = ?`, id, nonce)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO nonces (nonce, used_at) VALUES (?, ?)`, nonce, ms(at)); err != nil {
		if isConstraint(err) {
			return ErrConflict
		}
		return err
	}
	return tx.Commit()
}

// SetApprovalStatus makes the superseded/expired transitions, which are
// system-driven rather than decided by a human: a re-score that finds the
// impact digest changed supersedes the approval it no longer matches, and
// a background sweep expires one nobody acted on. Both are guarded the
// same way DecideApproval is: only a row still in `from` moves.
func (s *Store) SetApprovalStatus(ctx context.Context, id, from, to string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE approvals SET status = ? WHERE id = ? AND status = ?`, to, id, from)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}

// isConstraint reports whether err is a SQLite constraint violation (here,
// always the nonces primary key: two callers racing ConsumeApproval both
// pass the status check before either commits, so the nonce insert is
// the tiebreaker) rather than some other failure that ought to propagate
// as-is.
func isConstraint(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code()&0xff == sqlite3.SQLITE_CONSTRAINT
}
