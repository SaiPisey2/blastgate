import { useCallback, useEffect, useRef, useState } from 'react';
import { get, subscribe, type ApprovalDetail, type ApprovalSummary } from '../api';
import ApprovalCard, { type Outcome } from '../components/ApprovalCard';

const NOTES: Record<Outcome, string> = {
  approved: 'Approved. The agent can go ahead.',
  denied: 'Denied. The agent was refused.',
  gone: 'That request was already decided or has expired.',
};

export default function Queue() {
  const [items, setItems] = useState<ApprovalSummary[] | null>(null);
  const [details, setDetails] = useState<Record<string, ApprovalDetail>>({});
  const [error, setError] = useState('');
  const [note, setNote] = useState('');
  const idsRef = useRef<string>('');
  const fetched = useRef(new Set<string>());

  const load = useCallback(async () => {
    try {
      const list = await get<ApprovalSummary[]>('/api/approvals?status=pending');
      const rows = list ?? [];
      idsRef.current = rows.map((r) => r.id).sort().join(',');
      setItems(rows);
      setError('');
      // The list carries the summary line; the numbers, class and undo
      // come from each approval's detail.
      for (const r of rows) {
        if (fetched.current.has(r.id)) continue;
        fetched.current.add(r.id);
        get<ApprovalDetail>(`/api/approvals/${encodeURIComponent(r.id)}`).then(
          (d) => setDetails((prev) => ({ ...prev, [r.id]: d })),
          () => fetched.current.delete(r.id),
        );
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load the queue.');
    }
  }, []);

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
          <ApprovalCard key={s.id} summary={s} detail={details[s.id]} onDecided={decided} />
        ))}
      </div>
    </div>
  );
}
