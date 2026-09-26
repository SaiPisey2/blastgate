import { useCallback, useEffect, useRef, useState } from 'react';
import { get, subscribe, type ApprovalDetail, type ApprovalSummary } from '../api';
import ApprovalCard, { type Outcome } from '../components/ApprovalCard';

const NOTES: Record<Outcome, string> = {
  approved: 'Approved. The agent can go ahead.',
  denied: 'Denied. The agent was refused.',
  gone: 'That request was already decided or has expired.',
};

// oldestFirst orders the queue by when each hold was made, then by id so
// equal times keep one order. The server already sends them this way; the
// sort keeps the page right if it ever does not, since the oldest is the
// one closest to expiring. A time that does not parse sorts first rather
// than hiding at the bottom.
function oldestFirst(a: ApprovalSummary, b: ApprovalSummary): number {
  const ta = Date.parse(a.created);
  const tb = Date.parse(b.created);
  const ka = Number.isNaN(ta) ? -Infinity : ta;
  const kb = Number.isNaN(tb) ? -Infinity : tb;
  if (ka !== kb) return ka < kb ? -1 : 1;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

export default function Queue() {
  const [items, setItems] = useState<ApprovalSummary[] | null>(null);
  const [details, setDetails] = useState<Record<string, ApprovalDetail>>({});
  const [detailErrors, setDetailErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState('');
  const [note, setNote] = useState('');
  const idsRef = useRef<string>('');
  const fetched = useRef(new Set<string>());

  const fetchDetail = useCallback((id: string) => {
    fetched.current.add(id);
    setDetailErrors((prev) => {
      const { [id]: _drop, ...rest } = prev;
      return rest;
    });
    get<ApprovalDetail>(`/api/approvals/${encodeURIComponent(id)}`).then(
      (d) => setDetails((prev) => ({ ...prev, [id]: d })),
      // The card shows this with a retry; Approve stays disabled meanwhile,
      // because approving without the impact means approving blind.
      (e) => setDetailErrors((prev) => ({ ...prev, [id]: e instanceof Error ? e.message : 'request failed' })),
    );
  }, []);

  const load = useCallback(async () => {
    try {
      const list = await get<ApprovalSummary[]>('/api/approvals?status=pending');
      const rows = [...(list ?? [])].sort(oldestFirst);
      idsRef.current = rows.map((r) => r.id).sort().join(',');
      setItems(rows);
      setError('');
      // The list carries the summary line; the numbers, class and undo
      // come from each approval's detail.
      for (const r of rows) {
        if (!fetched.current.has(r.id)) fetchDetail(r.id);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load the queue.');
    }
  }, [fetchDetail]);

  useEffect(() => {
    void load();
    // The stream says which approvals are pending; refetch only when that
    // set changes, not on every heartbeat.
    return subscribe('approvals', (ev) => {
      if ([...ev.ids].sort().join(',') !== idsRef.current) void load();
    });
  }, [load]);

  function decided(id: string, outcome: Outcome) {
    setItems((prev) => {
      const next = (prev ?? []).filter((r) => r.id !== id);
      idsRef.current = next.map((r) => r.id).sort().join(',');
      return next;
    });
    setNote(NOTES[outcome]);
  }

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Approval queue</h1>
          <p className="lede">Requests blastgate held for a person to decide. Oldest first.</p>
        </div>
        {items !== null && items.length > 0 && <span className="page-count">{items.length} waiting</span>}
      </div>

      {note && (
        <p className="note" role="status">
          {note}
        </p>
      )}
      {error && (
        <p className="banner-error" role="alert">
          {error}
        </p>
      )}

      {items === null && !error && <p className="loading">Loading…</p>}

      {items !== null && items.length === 0 && (
        <div className="empty">
          <p className="empty-title">Nothing is waiting for you.</p>
          <p className="empty-sub">Held requests appear here the moment an agent makes one.</p>
        </div>
      )}

      <div className="cards">
        {items?.map((s) => (
          <ApprovalCard
            key={s.id}
            summary={s}
            detail={details[s.id]}
            detailError={detailErrors[s.id]}
            onRetry={() => fetchDetail(s.id)}
            onDecided={decided}
          />
        ))}
      </div>
    </div>
  );
}
