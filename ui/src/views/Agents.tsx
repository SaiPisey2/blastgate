import { useCallback, useEffect, useState } from 'react';
import { get, post, type Session } from '../api';
import { ARM_MS } from '../lib/friction';
import { duration, useNow } from '../lib/format';
import Button from '../components/Button';
import EmptyState from '../components/EmptyState';

// Live sessions first (the ones an approver might act on), newest first
// within each group.
function ordered(list: Session[]): Session[] {
  const live = (s: Session) => (s.state === 'active' ? 0 : 1);
  return [...list].sort((a, b) => live(a) - live(b) || Date.parse(b.created) - Date.parse(a.created));
}

type Status = { text: string; live: boolean };

// statusOf reads the same clock Stop's own visibility is gated on: a
// session already past its expires reads Expired even while the server
// still calls it active, so the two never disagree about whether
// stopping it would do anything.
function statusOf(s: Session, now: number): Status {
  if (s.state === 'revoked') return { text: 'Stopped', live: false };
  const msLeft = Date.parse(s.expires) - now;
  if (s.state === 'expired' || !(msLeft > 0)) return { text: 'Expired', live: false };
  return { text: `Active · ${duration(msLeft / 1000)} left`, live: true };
}

export default function Agents() {
  const [rows, setRows] = useState<Session[] | null>(null);
  const [error, setError] = useState('');
  const now = useNow(30_000);

  const load = useCallback(async () => {
    try {
      setRows(ordered((await get<Session[]>('/api/sessions')) ?? []));
      setError('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load the agents.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="page page-wide agents-page">
      <header className="page-head agents-head">
        <h1 className="page-title">Agents</h1>
        <p className="page-lede agents-lede">Who can act right now. Stop any of them.</p>
      </header>

      {error && (
        <p className="agents-banner-error" role="alert">
          {error}
        </p>
      )}
      {rows === null && !error && <p className="agents-loading">Loading…</p>}
      {rows !== null && rows.length === 0 && <EmptyState title="No agents have signed in." />}

      {rows !== null && rows.length > 0 && (
        <div className="agents-table-wrap">
          <table className="agents-table">
            <thead>
              <tr>
                <th scope="col">Agent</th>
                <th scope="col">On behalf of</th>
                <th scope="col">Status</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <Row key={s.id} s={s} now={now} onChanged={() => void load()} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Row({ s, now, onChanged }: { s: Session; now: number; onChanged: () => void }) {
  const [confirming, setConfirming] = useState(false);
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const status = statusOf(s, now);

  // The confirm control takes Stop's own place, so a double-click on Stop
  // lands its second click here: it stays inert for a moment, as on the
  // waiting cards, so a reflex click can never count as the decision.
  useEffect(() => {
    setArmed(false);
    if (!confirming) return;
    const t = setTimeout(() => setArmed(true), ARM_MS);
    return () => clearTimeout(t);
  }, [confirming]);

  async function stop() {
    setBusy(true);
    setError('');
    try {
      await post(`/api/sessions/${encodeURIComponent(s.id)}/revoke`);
      setConfirming(false);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'The agent was not stopped.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <tr>
      <td data-label="Agent">{s.agent}</td>
      <td data-label="On behalf of">{s.human}</td>
      <td data-label="Status" className={status.live ? 'agents-status-ok' : 'agents-status-off'}>
        {status.text}
      </td>
      <td data-label="" className="agents-row-actions">
        {status.live &&
          (confirming ? (
            <div className="agents-confirm">
              <span>
                Stop {s.agent} for {s.human}?
              </span>
              <span className="agents-confirm-buttons">
                <Button variant="quiet" onClick={() => setConfirming(false)} disabled={busy}>
                  Cancel
                </Button>
                <Button variant="danger" disabled={!armed || busy} onClick={() => void stop()}>
                  Stop
                </Button>
              </span>
            </div>
          ) : (
            <Button variant="quiet" onClick={() => setConfirming(true)}>
              Stop
            </Button>
          ))}
        {error && (
          <p className="agents-row-error" role="alert">
            {error}
          </p>
        )}
      </td>
    </tr>
  );
}
