import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { ApiError, get, subscribe, type ApprovalDetail, type Impact } from '../api';
import Button from '../components/Button';
import DecisionPanel, { undoLabel } from '../components/DecisionPanel';
import EmptyState from '../components/EmptyState';
import ImpactTree from '../components/ImpactTree';
import { GLYPH } from '../components/Tag';
import { actionText } from '../lib/format';
import { APPROVAL_ID } from '../router';

type Big = { label: string; value: string; tone?: 'danger' | 'caution' };

// bigNumbers is what approving would do, counted. An unmeasured impact's
// zeros mean "not looked at", not "nothing", so its counts read Unknown.
function bigNumbers(i: Impact): Big[] {
  const measured = i.measured === true;
  const count = (n: number, one: string, many: string): Big => ({
    label: measured && n === 1 ? one : many,
    value: measured ? String(n) : 'Unknown',
  });
  // A count that is not one (NaN, Infinity, negative, not a number) is
  // unknown, as frictionOf reads it: never a calm zero.
  const destroyedOK = typeof i.dataDestroyed === 'number' && Number.isFinite(i.dataDestroyed) && i.dataDestroyed >= 0;
  const destroyed = destroyedOK ? i.dataDestroyed : 0;
  const left = i.endpointsLeft && typeof i.endpointsLeft === 'object' ? i.endpointsLeft : {};
  const emptied = Object.values(left).filter((v) => v === 0).length;
  const pdbs = Array.isArray(i.pdbViolations) ? i.pdbViolations.length : 0;
  const effects = Array.isArray(i.effects) ? i.effects.length : 0;
  return [
    !destroyedOK
      ? { label: 'volumes destroyed', value: 'Unknown', tone: 'caution' }
      : { ...count(destroyed, 'volume destroyed', 'volumes destroyed'), tone: measured && destroyed > 0 ? 'danger' : undefined },
    count(effects, 'object affected', 'objects affected'),
    count(emptied, 'service left with no backends', 'services left with no backends'),
    count(pdbs, 'disruption budget broken', 'disruption budgets broken'),
    { label: 'Undo', value: undoLabel(i.undo) },
  ];
}

// me: the signed-in approver's name, for the panel's self-approval guard.
export default function Details({ id, me = '' }: { id: string; me?: string }) {
  // The router validates the id already; checked again so nothing that is
  // not an approval id is ever put into an API path.
  const valid = APPROVAL_ID.test(id);
  const [d, setD] = useState<ApprovalDetail | null>(null);
  const [error, setError] = useState('');
  const [missing, setMissing] = useState(!valid);
  const pending = useRef(false);
  const seq = useRef(0);
  const techId = useId();
  const affectedId = useId();

  const load = useCallback(async () => {
    if (!valid) return;
    const mine = ++seq.current;
    try {
      const got = await get<ApprovalDetail>(`/api/approvals/${encodeURIComponent(id)}`);
      if (mine !== seq.current) return;
      pending.current = got.status === 'pending';
      setD(got);
      setError('');
      setMissing(false);
    } catch (e) {
      if (mine !== seq.current) return;
      if (e instanceof ApiError && e.status === 404) setMissing(true);
      else setError(e instanceof Error ? e.message : 'Could not load this request.');
    }
  }, [id, valid]);

  useEffect(() => {
    setD(null);
    setError('');
    setMissing(!valid);
    pending.current = false;
    // Decided elsewhere (another approver, or it expired): it leaves the
    // pending set on the stream, and this page shows the new state.
    const off = subscribe('approvals', (ev) => {
      if (pending.current && !ev.ids.includes(id)) void load();
    });
    void load();
    return off;
  }, [id, valid, load]);

  if (missing) {
    return (
      <div className="page details">
        <EmptyState title="There is no such request." sub={<a href="#/waiting">Go to Waiting</a>} />
      </div>
    );
  }

  return (
    <div className="page details">
      <p className="details-back">
        <a href="#/waiting">Back to Waiting</a>
      </p>
      <h1 className="visually-hidden">Request details</h1>

      {error && (
        <div className="details-error" role="alert">
          <span>Couldn't load this request: {error}</span>
          <Button variant="quiet" onClick={() => void load()}>
            Retry
          </Button>
        </div>
      )}
      {d === null && !error && (
        <p className="details-loading" aria-busy="true">
          Loading…
        </p>
      )}

      {d && (
        <div className="details-grid">
          <div className="details-main">
            <DecisionPanel summary={d} detail={d} me={me} onRetry={() => void load()} onDecided={() => void load()} standalone />

            {d.impact ? (
              <ul className="big-numbers" aria-label="In numbers">
                {bigNumbers(d.impact).map((b) => (
                  <li key={b.label} className={b.tone ? `big-number tone-${b.tone}` : 'big-number'}>
                    {/* Colour, glyph and word: a tone never rides on colour alone. */}
                    {b.tone && (
                      <span className="big-number-glyph" aria-hidden="true">
                        {GLYPH[b.tone]}
                      </span>
                    )}
                    <span className="big-number-value">{b.value}</span>
                    <span className="big-number-label">{b.label}</span>
                  </li>
                ))}
              </ul>
            ) : null}

            {/* The command itself, in view (spec 4.2): what the agent
                will run is the one thing an approver should never have to
                open something to read. */}
            <pre className="details-action details-command mono" aria-label="Command">
              {actionText(d.action) || '(no action recorded)'}
            </pre>

            <details className="details-tech">
              <summary id={techId}>Technical details</summary>
              <dl className="details-facts" aria-labelledby={techId}>
                <Row label="Verb" value={d.verb} />
                <Row label="Resource" value={d.resource} />
                <Row label="Namespace" value={d.namespace} />
                <Row label="Name" value={d.name} />
                <Row label="Rule" value={d.rule} />
                <Row label="Approval id" value={d.id} />
              </dl>
              <pre className="details-action mono" aria-label="Request action">
                {actionText(d.action) || '(no action recorded)'}
              </pre>
            </details>
          </div>

          <section className="details-affected" aria-labelledby={affectedId}>
            <h2 id={affectedId} className="details-affected-title">
              What would be affected
            </h2>
            {d.impact ? <ImpactTree impact={d.impact} /> : <p className="itree-none">No impact was recorded for this request.</p>}
          </section>
        </div>
      )}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt>{label}</dt>
      <dd className="mono">{value || '(none)'}</dd>
    </>
  );
}
