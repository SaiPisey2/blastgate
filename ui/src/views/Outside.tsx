import { useEffect, useRef, useState } from 'react';
import { get, type BypassRow } from '../api';
import EmptyState from '../components/EmptyState';
import Sentence from '../components/Sentence';
import { describe, targetOf } from '../lib/describe';
import { clock } from '../lib/format';

// The first range matches the Activity banner (the last 24 hours), so
// following its link lands on the same count it showed.
const RANGES = [
  { hours: 24, label: 'Last 24 hours' },
  { hours: 168, label: 'Last 7 days' },
  { hours: 720, label: 'Last 30 days' },
];
const LIMIT = 500;

// Newest first whatever order the server sends; a row whose time does
// not parse sorts last rather than breaking the order of the rest.
function newestFirst(rows: BypassRow[]): BypassRow[] {
  const t = (r: BypassRow) => {
    const n = Date.parse(r.at);
    return Number.isNaN(n) ? -Infinity : n;
  };
  return [...rows].sort((a, b) => t(b) - t(a));
}

export default function Outside() {
  const [hours, setHours] = useState(24);
  const [rows, setRows] = useState<BypassRow[] | null>(null);
  const [error, setError] = useState('');
  const seq = useRef(0);

  useEffect(() => {
    // seq drops a slow answer for the range that was just replaced.
    const mine = ++seq.current;
    setRows(null);
    const q = new URLSearchParams({ since_hours: String(hours), limit: String(LIMIT) });
    get<BypassRow[]>(`/api/bypass?${q.toString()}`).then(
      (list) => {
        if (mine !== seq.current) return;
        setRows(newestFirst(list ?? []));
        setError('');
      },
      (e) => {
        if (mine !== seq.current) return;
        setError(e instanceof Error ? e.message : 'Could not load changes made outside blastgate.');
      },
    );
  }, [hours]);

  return (
    <div className="page page-wide outside">
      <p className="outside-back">
        <a href="#/activity">Back to Activity</a>
      </p>
      <div className="page-head outside-head">
        <div>
          <h1 className="page-title">Changes outside blastgate</h1>
          <p className="page-lede outside-lede">These writes reached the cluster without going through blastgate.</p>
        </div>
        <label className="outside-range">
          <span>Period</span>
          <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            {RANGES.map((r) => (
              <option key={r.hours} value={r.hours}>
                {r.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      {error && (
        <p className="outside-error" role="alert">
          {error}
        </p>
      )}
      {rows === null && !error && (
        <p className="outside-loading" aria-busy="true">
          Loading…
        </p>
      )}
      {rows !== null && rows.length === 0 && (
        <EmptyState
          title="No changes outside blastgate in this period."
          sub="If the webhook is not configured, nothing is recorded here, so an empty list proves nothing on its own."
        />
      )}
      {rows !== null && rows.length >= LIMIT && <p className="outside-cap">Showing the newest {LIMIT}. Choose a shorter period to see fewer at once.</p>}

      {rows !== null && rows.length > 0 && (
        <ul className="outside-list" aria-label="Changes outside blastgate">
          {rows.map((r, i) => {
            const what = describe({ verb: r.verb, resource: r.resource, subresource: r.subresource, namespace: r.namespace, name: r.name });
            const target = targetOf(r);
            const groups = r.groups ?? [];
            return (
              <li key={`${r.uid}-${r.at}-${i}`} className="outside-row">
                <time className="outside-when" dateTime={r.at} title={r.at}>
                  {clock(r.at)}
                </time>
                <div className="outside-who">
                  <span className="mono">{r.user}</span>
                  {groups.length > 0 && <span className="mono outside-groups">{groups.join(', ')}</span>}
                </div>
                <div className="outside-what">
                  <span>
                    <Sentence sentence={what.sentence} target={what.target} name={r.name} identClass="outside-ident" />
                  </span>
                  {target && <span className="mono outside-target">{target}</span>}
                </div>
                <div className="outside-flags">{r.dry_run && <span className="outside-dry">Dry run</span>}</div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
