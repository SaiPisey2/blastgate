import { useEffect, useRef, useState } from 'react';
import { get, type BypassRow } from '../api';
import { clock, target } from '../format';

const WINDOWS = [
  { hours: 24, label: 'Last 24 hours', phrase: 'the last 24 hours' },
  { hours: 168, label: 'Last 7 days', phrase: 'the last 7 days' },
  { hours: 720, label: 'Last 30 days', phrase: 'the last 30 days' },
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

export default function Bypass() {
  const [hours, setHours] = useState(168);
  const [rows, setRows] = useState<BypassRow[] | null>(null);
  const [error, setError] = useState('');
  const seq = useRef(0);

  useEffect(() => {
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
        setError(e instanceof Error ? e.message : 'Could not load bypass alerts.');
      },
    );
  }, [hours]);

  const phrase = WINDOWS.find((w) => w.hours === hours)?.phrase ?? `the last ${hours} hours`;

  return (
    <div className="page page-wide">
      <div className="page-head">
        <div>
          <h1>Bypass alerts</h1>
          <p className="lede">These writes reached the cluster without going through blastgate.</p>
        </div>
        <label className="field field-inline">
          <span>Window</span>
          <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            {WINDOWS.map((w) => (
              <option key={w.hours} value={w.hours}>
                {w.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      {error && (
        <p className="banner-error" role="alert">
          {error}
        </p>
      )}
      {rows === null && !error && <p className="loading">Loading…</p>}
      {rows !== null && rows.length === 0 && (
        <div className="empty">
          <p className="empty-title">No writes bypassed blastgate in {phrase}.</p>
          <p className="empty-sub">If the webhook is not configured, nothing is recorded here, so an empty list proves nothing on its own.</p>
        </div>
      )}
      {rows !== null && rows.length >= LIMIT && <p className="dim small">Showing the newest {LIMIT}. Narrow the window to see less at once.</p>}

      {rows !== null && rows.length > 0 && (
        <div className="table-wrap">
          <table className="feed">
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">User</th>
                <th scope="col">Groups</th>
                <th scope="col">Verb</th>
                <th scope="col">Resource</th>
                <th scope="col">Namespace / name</th>
                <th scope="col">Dry run</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={`${r.uid}-${r.at}-${i}`}>
                  <td data-label="Time" className="time" title={r.at}>
                    {clock(r.at)}
                  </td>
                  <td data-label="User" className="wrap">
                    {r.user}
                  </td>
                  <td data-label="Groups" className="wrap">
                    {(r.groups ?? []).length === 0 ? (
                      <span className="dim">—</span>
                    ) : (
                      <ul className="groups">
                        {(r.groups ?? []).map((g, j) => (
                          <li key={j}>{g}</li>
                        ))}
                      </ul>
                    )}
                  </td>
                  <td data-label="Verb" className="verb">
                    {r.verb}
                  </td>
                  <td data-label="Resource" className="resource wrap">
                    {/* One span: on narrow screens the cell is a flex row, and
                        loose pieces would be spaced apart as separate items. */}
                    <span>
                      {r.group && <span className="dim">{r.group}/</span>}
                      {r.resource}
                      {r.subresource && <span className="dim">/{r.subresource}</span>}
                    </span>
                  </td>
                  <td data-label="Namespace / name">{target(r.namespace, r.name)}</td>
                  <td data-label="Dry run">
                    {r.dry_run ? <span className="chip chip-neutral">dry run</span> : <span className="dim">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
