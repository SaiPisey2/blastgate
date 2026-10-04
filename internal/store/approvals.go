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
// approved or denied by a human (an access grant passes through
// partially_approved first, waiting for a second person), and — if approved — consumed exactly
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
	Status        string // pending | partially_approved | approved | denied | consumed | superseded | expired
	Created       time.Time
	Decided       time.Time
	Expires       time.Time
	DecidedBy     string
	Nonce         string
	Token         string
	// FirstApprover* record the first of two approvals on an access
	// grant; they stay set after the second person decides, so the row
	// names both.
	FirstApproverID   string
	FirstApproverName string
	FirstApproved     time.Time
}

const approvalCols = `id, session_id, human, agent, request_digest, impact_digest,
	action_json, impact_json, rule, status, created_at, decided_at, decided_by, nonce, token, expires_at,
	first_approver_id, first_approver_name, first_approved_at`

func scanApproval(row interface{ Scan(...any) error }) (Approval, error) {
	var a Approval
	var created, expires int64
	var decided, firstApproved sql.NullInt64
	if err := row.Scan(&a.ID, &a.Session, &a.Human, &a.Agent, &a.RequestDigest, &a.ImpactDigest,
		&a.ActionJSON, &a.ImpactJSON, &a.Rule, &a.Status, &created, &decided, &a.DecidedBy, &a.Nonce, &a.Token, &expires,
		&a.FirstApproverID, &a.FirstApproverName, &firstApproved); err != nil {
		return Approval{}, err
	}
	a.Created = time.UnixMilli(created).UTC()
	a.Expires = time.UnixMilli(expires).UTC()
	if decided.Valid {
		a.Decided = time.UnixMilli(decided.Int64).UTC()
	}
	a.FirstApproved = fromMS(firstApproved)
	return a, nil
}

// outboxEvent is the payload shape for both "approval.pending" and
// "approval.decided": small enough to read at a glance in the outbox
// table, and carrying only what a subscriber needs to go look the
// approval up itself rather than trusting a stale copy of its fields.
type outboxEvent struct {
	ApprovalID string `json:"approval_id"`
	Status     string `json:"status"`
	// FirstApproverName is set on "approval.partial" only, so the event
	// itself names the first of the two people, not just the row.
	FirstApproverName string `json:"first_approver_name,omitempty"`
}

func insertOutbox(ctx context.Context, tx *sql.Tx, kind, approvalID, status string, at time.Time) error {
	return insertOutboxEvent(ctx, tx, kind, outboxEvent{ApprovalID: approvalID, Status: status}, at)
}

func insertOutboxEvent(ctx context.Context, tx *sql.Tx, kind string, ev outboxEvent, at time.Time) error {
	payload, err := json.Marshal(ev)
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
	var firstApproved sql.NullInt64
	if !a.FirstApproved.IsZero() {
		firstApproved = sql.NullInt64{Int64: ms(a.FirstApproved), Valid: true}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO approvals (`+approvalCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Session, a.Human, a.Agent, a.RequestDigest, a.ImpactDigest,
		a.ActionJSON, a.ImpactJSON, a.Rule, a.Status, ms(a.Created), decided, a.DecidedBy, a.Nonce, a.Token, ms(a.Expires),
		a.FirstApproverID, a.FirstApproverName, firstApproved); err != nil {
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
// views. "pending" includes partially_approved: both are still waiting.
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

// ListPendingApprovals is the approver queue: pending (or partially
// approved, still waiting for a second person) approvals that can still
// be decided at now, oldest first, at most limit of them. Oldest
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
	return s.queryApprovals(ctx, `SELECT `+approvalCols+` FROM approvals WHERE status IN ('pending', 'partially_approved') AND expires_at >= ?
		ORDER BY created_at ASC, id ASC LIMIT ?`, ms(now), limit)
}

// ListLivePartialApprovals is the partially approved rows that can still
// be decided at now, oldest first, at most limit: the same live filter as
// ListPendingApprovals. A lapsed one would come back only to be shown as
// expired under a "partially approved" filter.
func (s *Store) ListLivePartialApprovals(ctx context.Context, now time.Time, limit int) ([]Approval, error) {
	if limit < 1 {
		return nil, nil
	}
	return s.queryApprovals(ctx, `SELECT `+approvalCols+` FROM approvals WHERE status = 'partially_approved' AND expires_at >= ?
		ORDER BY created_at ASC, id ASC LIMIT ?`, ms(now), limit)
}

// CountPendingApprovals is the true size of the queue ListPendingApprovals
// pages through, under the same filter: the badge used to be the length
// of a capped list, so it stopped counting at the cap.
func (s *Store) CountPendingApprovals(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM approvals WHERE status IN ('pending', 'partially_approved') AND expires_at >= ?`, ms(now)).Scan(&n)
	return n, err
}

// PendingQueue is ListPendingApprovals and CountPendingApprovals read by
// one statement, so both see the same rows: read apart, a hold landing
// between them gave a count that disagreed with the ids beside it.
func (s *Store) PendingQueue(ctx context.Context, now time.Time, limit int) ([]Approval, int, error) {
	if limit < 1 {
		n, err := s.CountPendingApprovals(ctx, now)
		return nil, n, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+approvalCols+`, COUNT(*) OVER () FROM approvals
		WHERE status IN ('pending', 'partially_approved') AND expires_at >= ?
		ORDER BY created_at ASC, id ASC LIMIT ?`, ms(now), limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Approval
	n := 0
	for rows.Next() {
		a, err := scanApproval(countScanner{rows, &n})
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, n, rows.Err()
}

// countScanner scans an approval row that ends with one extra count column.
type countScanner struct {
	rows *sql.Rows
	n    *int
}

func (c countScanner) Scan(dest ...any) error { return c.rows.Scan(append(dest, c.n)...) }

func (s *Store) listApprovals(ctx context.Context, status string, limit int) ([]Approval, error) {
	q := `SELECT ` + approvalCols + ` FROM approvals`
	var args []any
	switch status {
	case "":
	case "pending":
		// A partially approved row is still waiting (on its second
		// person); a "pending" list without it would hide exactly the
		// access grants half-way through being approved (ruling E-R2).
		q += ` WHERE status IN ('pending', 'partially_approved')`
	default:
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

// DecideApproval moves an approval to approved or denied. The WHERE
// clause is the compare-and-swap: two humans racing to decide the same
// approval must not both succeed, so only the first UPDATE that still
// finds it in the expected state takes effect and the second gets
// ErrConflict instead of silently overwriting the first decision.
//
// The expected state is pinned to what the caller checked. A deny stands
// in pending or partially_approved. An approval here is the single
// approver's and needs pending: a row that became partially approved
// between the caller's read and this write is an access grant, and a lone
// approval must not release it. The second of two approvals goes through
// ApproveSecond, which pins the first approver as well.
func (s *Store) DecideApproval(ctx context.Context, id, status, by, nonce, token string, decided, expires time.Time) error {
	where := `status IN ('pending', 'partially_approved')`
	if status != "denied" {
		where = `status = 'pending'`
	}
	return s.decide(ctx, id, status, by, nonce, token, decided, expires, where)
}

// liveFirstApprover is true when the row's first approver is a live
// approver account. A first approval counts only while its approver is
// live (ruling E-R15a): revoking a stolen account must withdraw what it
// already approved.
const liveFirstApprover = `EXISTS (SELECT 1 FROM approvers WHERE approvers.id = approvals.first_approver_id AND approvers.revoked_at IS NULL)`

// ApproveSecond is the second approval of an access grant: it releases
// only if the row is still partially approved by firstApproverID -- the
// first approver the caller compared against -- and both that approver
// and the one approving now (byID) are still live, all inside the same
// UPDATE. Without the pin, a first approver replaced or revoked between
// the caller's read and this write would still be the "other person" the
// release rests on; and an account revoked between its sign-in check and
// this write must not supply the second approval either.
func (s *Store) ApproveSecond(ctx context.Context, id, firstApproverID, byID, by, nonce, token string, decided, expires time.Time) error {
	return s.decide(ctx, id, "approved", by, nonce, token, decided, expires,
		`status = 'partially_approved' AND first_approver_id = ? AND `+liveFirstApprover+
			` AND EXISTS (SELECT 1 FROM approvers WHERE approvers.id = ? AND approvers.revoked_at IS NULL)`, firstApproverID, byID)
}

func (s *Store) decide(ctx context.Context, id, status, by, nonce, token string, decided, expires time.Time, where string, args ...any) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, nonce = ?, token = ?, expires_at = ? WHERE id = ? AND `+where,
		append([]any{status, ms(decided), by, nonce, token, ms(expires), id}, args...)...)
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

// ReplaceFirstApprover makes approverID the first approver of an access
// grant whose recorded first approver, revokedID, is no longer live
// (ruling E-R15a). The row stays partially approved and nothing is
// minted: the arriving approval becomes the first of two, never the
// second, so a revoked account's approval can never be half of a release.
// The UPDATE re-checks that the first approver is still revokedID and
// still not live, so a live first approver is never overwritten.
func (s *Store) ReplaceFirstApprover(ctx context.Context, id, revokedID, approverID, approverName string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`UPDATE approvals SET first_approver_id = ?, first_approver_name = ?, first_approved_at = ?
		 WHERE id = ? AND status = 'partially_approved' AND first_approver_id = ? AND NOT `+liveFirstApprover,
		approverID, approverName, ms(at), id, revokedID)
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
	if err := insertOutboxEvent(ctx, tx, "approval.partial", outboxEvent{ApprovalID: id, Status: "partially_approved", FirstApproverName: approverName}, at); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkPartiallyApproved records the first of two approvals on an access
// grant. Only a pending row moves: a second first-approval racing this
// one, or one arriving after the second person decided, gets ErrConflict
// rather than overwriting who approved first. The outbox event is written
// in the same transaction so the record of the first person never exists
// without the state change, or the reverse.
func (s *Store) MarkPartiallyApproved(ctx context.Context, id, approverID, approverName string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`UPDATE approvals SET status = 'partially_approved', first_approver_id = ?, first_approver_name = ?, first_approved_at = ?
		 WHERE id = ? AND status = 'pending'`,
		approverID, approverName, ms(at), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM approvals WHERE id = ?`, id).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return ErrConflict
	}
	if err := insertOutboxEvent(ctx, tx, "approval.partial", outboxEvent{ApprovalID: id, Status: "partially_approved", FirstApproverName: approverName}, at); err != nil {
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
