import { useCallback, useEffect, useState } from 'react';
import { ApiError, get, post, type Session } from '../api';
import { ARM_MS } from '../components/ApprovalCard';
import { clock } from '../format';

const STATES: Record<string, string> = { active: 'calm', expired: 'neutral', revoked: 'danger' };

// Live sessions first (those are the ones to act on), newest first within.
function ordered(list: Session[]): Session[] {
  const live = (s: Session) => (s.state === 'active' ? 0 : 1);
  return [...list].sort((a, b) => live(a) - live(b) || Date.parse(b.created) - Date.parse(a.created));
}

export default function Sessions() {
  const [rows, setRows] = useState<Session[] | null>(null);
  const [error, setError] = useState('');
  const [note, setNote] = useState('');

  const load = useCallback(async () => {
    try {
      setRows(ordered((await get<Session[]>('/api/sessions')) ?? []));
      setError('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load the sessions.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  function revoked(s: Session) {
    setNote(`Revoked. ${s.agent} for ${s.human} can no longer use its token.`);
    setRows((prev) => (prev ?? []).map((r) => (r.id === s.id ? { ...r, state: 'revoked' } : r)));
    void load();
  }

  return (
    <div className="page page-wide">
      <div className="page-head">
        <div>
          <h1>Agent sessions</h1>
          <p className="lede">Each agent signs in on behalf of a person. Revoking a session stops its token at once.</p>
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
      {rows === null && !error && <p className="loading">Loading…</p>}
      {rows !== null && rows.length === 0 && (
        <div className="empty">
          <p className="empty-title">No agent sessions.</p>
          <p className="empty-sub">
            An agent gets one with <code>blastgate session new</code>.
          </p>
        </div>
      )}

      {rows !== null && rows.length > 0 && (
        <div className="table-wrap">
          <table className="feed">
            <thead>
              <tr>
                <th scope="col">Human</th>
                <th scope="col">Agent</th>
                <th scope="col">Created</th>
                <th scope="col">Expires</th>
                <th scope="col">State</th>
                <th scope="col">Session</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <Row key={s.id} s={s} onRevoked={revoked} onGone={() => void load()} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Row({ s, onRevoked, onGone }: { s: Session; onRevoked: (s: Session) => void; onGone: () => void }) {
  const [confirming, setConfirming] = useState(false);
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  // The confirm button takes Revoke's place, so a double-click on Revoke
  // would land on it: it stays inert for a moment, as on approval cards.
  useEffect(() => {
    setArmed(false);
    if (!confirming) return;
    const t = setTimeout(() => setArmed(true), ARM_MS);
    return () => clearTimeout(t);
  }, [confirming]);

  async function revoke() {
    setBusy(true);
    setError('');
    try {
      await post(`/api/sessions/${encodeURIComponent(s.id)}/revoke`);
      setConfirming(false);
      onRevoked(s);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        setConfirming(false);
        onGone();
      } else setError(e instanceof Error ? e.message : 'The session was not revoked.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <tr className={s.state === 'active' ? '' : 'muted'}>
      <td data-label="Human">{s.human}</td>
      <td data-label="Agent">{s.agent}</td>
      <td data-label="Created" className="time" title={s.created}>
        {clock(s.created)}
      </td>
      <td data-label="Expires" className="time" title={s.expires}>
        {clock(s.expires)}
      </td>
      <td data-label="State">
        <span className={`chip chip-${Object.hasOwn(STATES, s.state) ? STATES[s.state] : 'neutral'}`}>{s.state}</span>
      </td>
      <td data-label="Session">
        <code className="rule">{s.id}</code>
      </td>
      <td data-label="" className="row-actions">
        {s.state === 'active' &&
          (confirming ? (
            <div className="row-confirm">
              <span>Revoke? The agent&apos;s token stops working at once.</span>
              <span className="buttons">
                <button type="button" className="btn btn-ghost btn-small" onClick={() => setConfirming(false)} disabled={busy}>
                  Cancel
                </button>
                <button type="button" className="btn btn-danger btn-small" disabled={!armed || busy} onClick={() => void revoke()}>
                  Confirm revoke
                </button>
              </span>
            </div>
          ) : (
            <button type="button" className="btn btn-secondary btn-small" onClick={() => setConfirming(true)}>
              Revoke
            </button>
          ))}
        {error && (
          <p className="card-error" role="alert">
            {error}
          </p>
        )}
      </td>
    </tr>
  );
}
