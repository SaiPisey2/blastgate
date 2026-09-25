import { useState } from 'react';
import { ApiError, post, type ApprovalDetail, type ApprovalSummary } from '../api';
import ClassBadge from './ClassBadge';
import { duration, plural, target, useNow } from '../format';

export type Outcome = 'approved' | 'denied' | 'gone';

type Props = {
  summary: ApprovalSummary;
  detail?: ApprovalDetail;
  onDecided: (id: string, outcome: Outcome) => void;
};

type Severity = 'severe' | 'warn' | 'calm';

// A static prompt that looks the same every time is a prompt people learn
// to click through. So the card's weight follows what approving would do:
// destructive and power-granting changes look and act differently from a
// reversible patch, and destroying data takes a typed confirmation.
function severityOf(d?: ApprovalDetail): Severity {
  if (!d) return 'calm';
  const cls = d.impact.class;
  if (cls === 'TERMINAL' || cls === 'AUTHORITY' || d.impact.dataDestroyed > 0) return 'severe';
  if (cls === 'COMPENSABLE') return 'warn';
  return 'calm';
}

function undoText(undo: string): string {
  switch (undo) {
    case 'objects':
      return 'The objects are snapshotted first and can be restored.';
    case 'none':
      return 'No undo. This cannot be taken back.';
    case '':
      return 'Unknown.';
  }
  return undo;
}

export default function ApprovalCard({ summary: s, detail, onDecided }: Props) {
  const now = useNow();
  const [confirming, setConfirming] = useState<'approve' | 'deny' | null>(null);
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const severity = severityOf(detail);
  const impact = detail?.impact;
  const destroys = (impact?.dataDestroyed ?? 0) > 0;
  // A cluster-scoped delete (a Namespace, a PV) has no namespace; the
  // object's own name is then the thing to type.
  const phrase = s.namespace || s.name;
  const needsTyping = confirming === 'approve' && destroys;
  const created = Date.parse(s.created);
  const age = Number.isNaN(created) ? s.age_seconds : (now - created) / 1000;
  const expires = Date.parse(s.expires);
  const emptied = Object.values(impact?.endpointsLeft ?? {}).filter((n) => n === 0).length;

  async function decide(action: 'approve' | 'deny') {
    setBusy(true);
    setError('');
    try {
      await post(`/api/approvals/${encodeURIComponent(s.id)}/${action}`);
      onDecided(s.id, action === 'approve' ? 'approved' : 'denied');
    } catch (e) {
      // 409: someone else decided it, or it expired, while this card was
      // open. 404: it no longer exists. Either way it is not ours to decide.
      if (e instanceof ApiError && (e.status === 409 || e.status === 404)) {
        onDecided(s.id, 'gone');
        return;
      }
      setError(e instanceof Error ? e.message : 'The decision did not go through.');
      setBusy(false);
    }
  }

  function cancel() {
    setConfirming(null);
    setTyped('');
    setError('');
  }

  return (
    <article className={`card approval sev-${severity}`} data-severity={severity} aria-label={`${s.verb} ${s.resource} ${phrase}`}>
      <div className="card-head">
        <div className="card-tags">
          {impact ? <ClassBadge cls={impact.class} /> : <span className="badge badge-neutral">measuring…</span>}
          <span className="held-by">
            held by <code className="rule">{s.rule}</code>
          </span>
        </div>
        <span className="age" title={s.created}>
          {duration(age)}
          {duration(age) !== 'just now' && ' ago'}
        </span>
      </div>

      <div className="what">
        <div className="what-verb">
          <span className="verb">{s.verb}</span> <span className="resource">{s.resource}</span>
        </div>
        <div className="what-target">{target(s.namespace, s.name)}</div>
        <div className="requester">
          <span>{s.human}</span> <span className="dim">via</span> <span>{s.agent}</span>
          {!Number.isNaN(expires) && <span className="dim"> · expires in {duration((expires - now) / 1000)}</span>}
        </div>
      </div>

      <section className="impact" aria-label="Impact">
        <p className="impact-line">{s.summary}</p>
        {impact && (
          <>
            <dl className="stats">
              <Stat n={impact.effects?.length ?? 0} label={plural(impact.effects?.length ?? 0, 'object affected', 'objects affected')} />
              <Stat n={impact.dataDestroyed} label={plural(impact.dataDestroyed, 'volume destroyed', 'volumes destroyed')} alarm />
              <Stat n={emptied} label={plural(emptied, 'service emptied', 'services emptied')} alarm />
              <Stat n={impact.pdbViolations?.length ?? 0} label={plural(impact.pdbViolations?.length ?? 0, 'budget broken', 'budgets broken')} alarm />
            </dl>
            {impact.reason && <p className="reason">{impact.reason}</p>}
            <p className="undo">
              <span className="undo-label">Undo</span> <span>{undoText(impact.undo)}</span>
            </p>
          </>
        )}
      </section>

      {error && (
        <p className="card-error" role="alert">
          {error}
        </p>
      )}

      {confirming === null ? (
        <div className="actions">
          <a className="details-link" href={`#/approvals/${encodeURIComponent(s.id)}`}>
            Details
          </a>
          <div className="buttons">
            <button type="button" className="btn btn-secondary" onClick={() => setConfirming('deny')}>
              Deny
            </button>
            {/* Approve waits for the impact: approving before it loads would
                skip the severity cues and the typed confirmation. */}
            <button type="button" className={severity === 'severe' ? 'btn btn-danger' : 'btn btn-primary'} disabled={!detail} onClick={() => setConfirming('approve')}>
              Approve
            </button>
          </div>
        </div>
      ) : (
        <form
          className={`confirm confirm-${confirming}`}
          onSubmit={(e) => {
            e.preventDefault();
            if (!busy && (!needsTyping || typed === phrase)) void decide(confirming);
          }}
        >
          {needsTyping ? (
            <label className="typed">
              <span>
                This destroys data. Type <code>{phrase}</code> to approve
              </span>
              <input type="text" value={typed} onChange={(e) => setTyped(e.target.value)} autoFocus autoComplete="off" spellCheck={false} />
            </label>
          ) : (
            <p className="confirm-text">{confirming === 'approve' ? 'Approve this request? The agent will be let through.' : 'Deny this request? The agent will be refused.'}</p>
          )}
          <div className="buttons">
            <button type="button" className="btn btn-ghost" onClick={cancel} disabled={busy}>
              Cancel
            </button>
            <button
              type="submit"
              className={confirming === 'deny' ? 'btn btn-secondary' : severity === 'severe' ? 'btn btn-danger' : 'btn btn-primary'}
              disabled={busy || (needsTyping && typed !== phrase)}
              autoFocus={!needsTyping}
            >
              {confirming === 'approve' ? 'Confirm approve' : 'Confirm deny'}
            </button>
          </div>
        </form>
      )}
    </article>
  );
}

function Stat({ n, label, alarm }: { n: number; label: string; alarm?: boolean }) {
  return (
    <div className={n === 0 ? 'stat zero' : alarm ? 'stat alarm' : 'stat'}>
      <dt>{label}</dt>
      <dd>{n}</dd>
    </div>
  );
}
