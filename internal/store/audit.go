package store

import (
	"context"
	"slices"
	"time"
)

// AuditRow is one line of the append-only audit trail: a "decision" row is
// written before a mutating request is forwarded or held, a "result" row
// after the upstream responds (or the request is refused outright). Every
// field is stored, never derived, so the trail reads the same after the
// policy or scorer that produced it has changed.
type AuditRow struct {
	// ID is the audit table's rowid: zero on a row not yet read back, since
	// AppendAudit never learns it (the insert doesn't ask for it) and
	// paging needs it as the cursor, not the row's content.
	ID        int64
	At        time.Time
	Kind      string // "decision" | "result"
	RequestID string
	Session   string
	Human     string
	Agent     string
	Source    string

	Verb        string
	Group       string
	Resource    string
	Subresource string
	Namespace   string
	Name        string

	RequestDigest string
	ActionJSON    []byte
	ImpactJSON    []byte
	LabelsJSON    []byte

	Class      string
	Measured   bool
	Rule       string
	Decision   string
	ApprovalID string

	Status    int
	Outcome   string
	LatencyMS int64
	Snapshot  string
}

const auditCols = `at, kind, request_id, session_id, human, agent, source,
	verb, grp, resource, subresource, namespace, name,
	request_digest, action_json, impact_json, labels_json,
	class, measured, rule, decision, approval_id,
	status, outcome, latency_ms, snapshot`

// auditSelectCols adds the rowid to auditCols for reads; inserts never use
// it since `id` is autoincrement and not supplied by the caller.
const auditSelectCols = `id, ` + auditCols

// AppendAudit writes one row. There is no update path: the table's
// UPDATE/DELETE triggers abort, so a correction is a new row, not an edit
// of history.
func (s *Store) AppendAudit(ctx context.Context, r AuditRow) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit (`+auditCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ms(r.At), r.Kind, r.RequestID, r.Session, r.Human, r.Agent, r.Source,
		r.Verb, r.Group, r.Resource, r.Subresource, r.Namespace, r.Name,
		r.RequestDigest, r.ActionJSON, r.ImpactJSON, r.LabelsJSON,
		r.Class, boolToInt(r.Measured), r.Rule, r.Decision, r.ApprovalID,
		r.Status, r.Outcome, r.LatencyMS, r.Snapshot)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func scanAudit(row interface{ Scan(...any) error }) (AuditRow, error) {
	var r AuditRow
	var at int64
	var measured int
	if err := row.Scan(&r.ID, &at, &r.Kind, &r.RequestID, &r.Session, &r.Human, &r.Agent, &r.Source,
		&r.Verb, &r.Group, &r.Resource, &r.Subresource, &r.Namespace, &r.Name,
		&r.RequestDigest, &r.ActionJSON, &r.ImpactJSON, &r.LabelsJSON,
		&r.Class, &measured, &r.Rule, &r.Decision, &r.ApprovalID,
		&r.Status, &r.Outcome, &r.LatencyMS, &r.Snapshot); err != nil {
		return AuditRow{}, err
	}
	r.At = time.UnixMilli(at).UTC()
	r.Measured = measured != 0
	return r, nil
}

// AuditSince returns rows at or after `since`, oldest first: audit reads
// replay history in the order it happened, not the order sqlite happened
// to store it. kind == "" returns every kind.
func (s *Store) AuditSince(ctx context.Context, since time.Time, kind string) ([]AuditRow, error) {
	return s.auditSince(ctx, since, kind, 0)
}

// AuditSinceLimit is AuditSince keeping only the newest limit rows of the
// window, still returned oldest first. A caller serving a request (the
// admin API's replay) must not load a whole month of audit into memory
// because one approver asked; it fetches one row past its cap to learn
// whether there were more, and that extra row is the oldest one, at
// index 0. The newest rows, not the oldest, because a window too big to
// evaluate whole should answer for what the gateway sees now (P2-R21).
// A limit below 1 returns nothing rather than meaning "no limit".
func (s *Store) AuditSinceLimit(ctx context.Context, since time.Time, kind string, limit int) ([]AuditRow, error) {
	if limit < 1 {
		return nil, nil
	}
	return s.auditSince(ctx, since, kind, limit)
}

func (s *Store) auditSince(ctx context.Context, since time.Time, kind string, limit int) ([]AuditRow, error) {
	q := `SELECT ` + auditSelectCols + ` FROM audit WHERE at >= ?`
	args := []any{ms(since)}
	if kind != "" {
		q += ` AND kind = ?`
		args = append(args, kind)
	}
	// A bounded read walks back from the newest row, so LIMIT cuts the
	// oldest end of the window; it is put back in order below.
	if limit > 0 {
		q += ` ORDER BY at DESC, id DESC LIMIT ?`
		args = append(args, limit)
	} else {
		q += ` ORDER BY at ASC, id ASC`
	}
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if limit > 0 {
		slices.Reverse(out)
	}
	return out, nil
}
