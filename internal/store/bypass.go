package store

import (
	"context"
	"encoding/json"
	"time"
)

// BypassRow is one AdmissionReview the webhook let through unconditionally
// (the webhook never denies) and only recorded. It carries the request's
// identity and target exactly like AuditRow does for the proxy path, so
// the two can be read side by side, but has no decision, class, or
// outcome: nothing here was ever evaluated.
type BypassRow struct {
	At     time.Time
	User   string
	Groups []string

	Verb        string
	Group       string
	Resource    string
	Subresource string
	Namespace   string
	Name        string
	UID         string

	DryRun bool
}

const bypassCols = `at, user, groups_json, verb, grp, resource, subresource, namespace, name, uid, dry_run`

// AppendBypass writes one row. Like audit, the table is append-only
// (UPDATE/DELETE abort via triggers): a bypass record is evidence the
// webhook let something through, and evidence doesn't get edited after
// the fact.
func (s *Store) AppendBypass(ctx context.Context, b BypassRow) error {
	groups, err := json.Marshal(b.Groups)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO bypass (`+bypassCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		ms(b.At), b.User, groups, b.Verb, b.Group, b.Resource, b.Subresource, b.Namespace, b.Name, b.UID, boolToInt(b.DryRun))
	return err
}

func scanBypass(row interface{ Scan(...any) error }) (BypassRow, error) {
	var b BypassRow
	var at int64
	var groups []byte
	var dryRun int
	if err := row.Scan(&at, &b.User, &groups, &b.Verb, &b.Group, &b.Resource, &b.Subresource, &b.Namespace, &b.Name, &b.UID, &dryRun); err != nil {
		return BypassRow{}, err
	}
	b.At = time.UnixMilli(at).UTC()
	b.DryRun = dryRun != 0
	if len(groups) > 0 {
		if err := json.Unmarshal(groups, &b.Groups); err != nil {
			return BypassRow{}, err
		}
	}
	return b, nil
}

// BypassSince returns bypass rows at or after `since`, newest first,
// capped at limit: the admin UI's bypass view wants the most recent
// activity, not a scan from the beginning of a table every controller in
// the cluster writes to.
func (s *Store) BypassSince(ctx context.Context, since time.Time, limit int) ([]BypassRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+bypassCols+` FROM bypass WHERE at >= ? ORDER BY at DESC, id DESC LIMIT ?`, ms(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BypassRow
	for rows.Next() {
		b, err := scanBypass(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
