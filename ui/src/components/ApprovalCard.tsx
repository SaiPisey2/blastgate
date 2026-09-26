import { useEffect, useRef, useState } from 'react';
import { ApiError, post, type ApprovalDetail, type ApprovalSummary } from '../api';
import ClassBadge from './ClassBadge';
import { duration, plural, target, useNow } from '../format';

export type Outcome = 'approved' | 'denied' | 'gone';

type Props = {
  summary: ApprovalSummary;
  detail?: ApprovalDetail;
  detailError?: string;
  onRetry: () => void;
  onDecided: (id: string, outcome: Outcome) => void;
};

// How long the confirm button stays inert after the confirm step opens:
// long enough that a double-click on Approve cannot also confirm.
export const ARM_MS = 300;

type Severity = 'severe' | 'warn' | 'calm';

// A static prompt that looks the same every time is a prompt people learn
// to click through. So the card's weight follows what approving would do:
// destructive and power-granting changes look and act differently from a
// reversible patch, and destroying data takes a typed confirmation.
// It is computed from the summary, which the list already carries, so it
// is right from the first paint and does not depend on a second request.
//
// It fails closed: only the classes named here as safe are calm or warn.
// A missing, empty or unknown class (an unmeasured action, or a class the
// engine adds later) is severe, never calm by default.
const KNOWN_CLASSES = new Set(['READ', 'REVERSIBLE', 'COMPENSABLE', 'TERMINAL', 'AUTHORITY']);

export function isKnownClass(cls: string): boolean {
  return KNOWN_CLASSES.has(cls);
}

function severityOf(s: ApprovalSummary): Severity {
  if (s.data_destroyed > 0) return 'severe';
  if (s.class === 'READ' || s.class === 'REVERSIBLE') return 'calm';
  if (s.class === 'COMPENSABLE') return 'warn';
  return 'severe';
}

// confirmPhrase is what must be typed to approve destroying data. A
// cluster-scoped request can have neither namespace nor name (a
// deletecollection of persistentvolumes) and that is the most destructive
// kind there is, so the phrase falls back to the resource and is never
// empty: an empty phrase would make the typed confirmation a no-op.
export function confirmPhrase(s: ApprovalSummary): string {
  return s.namespace || s.name || s.resource || s.verb || 'approve';
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

export default function ApprovalCard({ summary: s, detail, detailError, onRetry, onDecided }: Props) {
  const now = useNow();
  const [confirming, setConfirming] = useState<'approve' | 'deny' | null>(null);
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [armed, setArmed] = useState(false);
  const confirmRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setArmed(false);
    if (confirming === null) return;
    const t = setTimeout(() => setArmed(true), ARM_MS);
    return () => clearTimeout(t);
  }, [confirming]);

  const severity = severityOf(s);
  const impact = detail?.impact;
  // Either source saying data is destroyed is enough to demand typing.
  const destroys = s.data_destroyed > 0 || (impact?.dataDestroyed ?? 0) > 0;
  // An unmeasured or unknown class reports data_destroyed 0 because nothing
  // was measured, not because nothing is destroyed: it is typed too.
  const unknown = !isKnownClass(s.class);
  const phrase = confirmPhrase(s);
  const needsTyping = confirming === 'approve' && (destroys || unknown);

  // Only a calm card moves focus to its confirm button (once it is armed;
  // a disabled button cannot take focus). On a severe or compensable card,
  // Enter must not be a reflex away from yes.
  useEffect(() => {
    if (armed && !needsTyping && severity === 'calm') confirmRef.current?.focus();
  }, [armed, needsTyping, severity]);
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
          <ClassBadge cls={s.class} />
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
        {detailError && (
          <div className="detail-error" role="alert">
            <span>Could not load the impact: {detailError}</span>
            <button type="button" className="btn btn-secondary btn-small" onClick={onRetry}>
              Retry
            </button>
          </div>
        )}
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
            if (armed && !busy && (!needsTyping || typed === phrase)) void decide(confirming);
          }}
        >
          {needsTyping ? (
            <label className="typed">
              <span>
                {destroys ? 'This destroys data.' : 'The impact of this was not measured.'} Type <code>{phrase}</code> to approve
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
              ref={confirmRef}
              disabled={!armed || busy || (needsTyping && typed !== phrase)}
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
