package store

import (
	"context"
	"time"
)

// AuditRow is one line of the append-only audit trail: a "decision" row is
// written before a mutating request is forwarded or held, a "result" row
// after the upstream responds (or the request is refused outright). Every
// field is stored, never derived, so the trail reads the same after the
// policy or scorer that produced it has changed.
type AuditRow struct {
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
	if err := row.Scan(&at, &r.Kind, &r.RequestID, &r.Session, &r.Human, &r.Agent, &r.Source,
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
	q := `SELECT ` + auditCols + ` FROM audit WHERE at >= ?`
	args := []any{ms(since)}
	if kind != "" {
		q += ` AND kind = ?`
		args = append(args, kind)
	}
	q += ` ORDER BY at ASC, id ASC`
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
