import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, get, subscribe, type ApprovalDetail } from '../api';
import ApprovalCard, { type Outcome } from '../components/ApprovalCard';
import ImpactTree from '../components/ImpactTree';
import { actionText, shellQuote } from '../lib/format';

const NOTES: Record<Outcome, string> = {
  approved: 'Approved. The agent can go ahead.',
  denied: 'Denied. The agent was refused.',
  gone: 'That request was already decided or has expired.',
};

// actionText and shellQuote moved to lib/format; re-exported here until
// Task 9 retires this view.
export { actionText, shellQuote };

export default function Approval({ id }: { id: string }) {
  const [d, setD] = useState<ApprovalDetail | null>(null);
  const [error, setError] = useState('');
  const [missing, setMissing] = useState(false);
  const [note, setNote] = useState('');
  const pending = useRef(false);

  const load = useCallback(async () => {
    try {
      const got = await get<ApprovalDetail>(`/api/approvals/${encodeURIComponent(id)}`);
      pending.current = got.status === 'pending';
      setD(got);
      setError('');
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) setMissing(true);
      else setError(e instanceof Error ? e.message : 'Could not load the approval.');
    }
  }, [id]);

  useEffect(() => {
    setD(null);
    setMissing(false);
    setNote('');
    void load();
    // Decided elsewhere (another approver, or it expired): it leaves the
    // pending set on the stream, and this page shows the new state.
    return subscribe('approvals', (ev) => {
      if (pending.current && !ev.ids.includes(id)) void load();
    });
  }, [id, load]);

  function decided(_id: string, outcome: Outcome) {
    setNote(NOTES[outcome]);
    void load();
  }

  return (
    <div className="page">
      <p className="back">
        <a href="#/queue">← Queue</a>
      </p>
      <div className="page-head">
        <div>
          <h1>Approval</h1>
          <p className="lede">What approving this request would do, object by object.</p>
        </div>
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
      {missing && (
        <div className="empty">
          <p className="empty-title">There is no approval with this id.</p>
          <p className="empty-sub">
            <a href="#/queue">Go to the queue</a>
          </p>
        </div>
      )}
      {d === null && !error && !missing && <p className="loading">Loading…</p>}

      {d && (
        <div className="cards">
          <ApprovalCard summary={d} detail={d} onRetry={() => void load()} onDecided={decided} standalone />

          <section className="card section">
            <h2>Action</h2>
            <pre className="code-block" aria-label="Action">
              {actionText(d.action) || '(no action recorded)'}
            </pre>
          </section>

          <section className="card section">
            <h2>Impact</h2>
            {d.impact ? <ImpactTree impact={d.impact} /> : <p className="dim">No impact was recorded for this request.</p>}
          </section>
        </div>
      )}
    </div>
  );
}
