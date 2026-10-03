package store

import (
	"context"
	"time"
)

// RuleStats is how one policy rule's holds were resolved within a window.
// Held counts every hold, including those still waiting; Approved counts
// every hold a person let through, whether or not the agent has used it
// yet (consumed) or a re-score later replaced it (superseded).
type RuleStats struct {
	Rule                            string
	Held, Approved, Denied, Expired int
}

// PolicyStats aggregates approvals created at or after since, per rule,
// most-held first and then by name so the order is stable. It reads the
// approvals table, not the audit trail: an approval row is the one record
// of how a hold ended.
//
// A pending or partially approved row past its expiry at now counts as
// expired: nothing moves it to "expired" unless the agent retries, and it
// usually never does, so the status column alone under-counts the holds
// nobody answered. now is passed in, not read here, so the caller's clock
// (and a test's) decides what has lapsed.
func (s *Store) PolicyStats(ctx context.Context, since, now time.Time) ([]RuleStats, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT rule,
		COUNT(*) AS held,
		SUM(CASE WHEN status IN ('approved', 'consumed', 'superseded') THEN 1 ELSE 0 END),
		SUM(CASE WHEN status = 'denied' THEN 1 ELSE 0 END),
		SUM(CASE WHEN status = 'expired'
			OR (status IN ('pending', 'partially_approved') AND expires_at < ?) THEN 1 ELSE 0 END)
		FROM approvals WHERE created_at >= ?
		GROUP BY rule ORDER BY held DESC, rule ASC`, ms(now), ms(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleStats
	for rows.Next() {
		var r RuleStats
		if err := rows.Scan(&r.Rule, &r.Held, &r.Approved, &r.Denied, &r.Expired); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
