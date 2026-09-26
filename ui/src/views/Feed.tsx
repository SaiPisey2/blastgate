import { useEffect, useRef, useState } from 'react';
import { get, onStreamStatus, streamStatus, subscribe, type FeedRow, type StreamStatus } from '../api';
import ClassBadge, { DecisionChip } from '../components/ClassBadge';
import { clock, target } from '../format';
import { displayClass, fold, keyOf, minRawId, type Entry } from '../lib/feedModel';
import { APPROVAL_ID } from '../router';

const PAGE = 50;
const CLASSES = ['READ', 'REVERSIBLE', 'COMPENSABLE', 'TERMINAL', 'AUTHORITY'];
const DECISIONS = ['allow', 'hold', 'deny'];

type Filters = { agent: string; human: string; class: string; decision: string };
const EMPTY: Filters = { agent: '', human: '', class: '', decision: '' };

function query(f: Filters, before?: number): string {
  const p = new URLSearchParams({ limit: String(PAGE) });
  if (before !== undefined) p.set('before', String(before));
  for (const k of ['agent', 'human', 'class', 'decision'] as const) {
    const v = f[k].trim();
    if (v) p.set(k, v);
  }
  return `/api/feed?${p.toString()}`;
}

const LIVE_LABELS: Record<StreamStatus, string> = {
  connecting: 'Connecting',
  live: 'Live',
  reconnecting: 'Reconnecting',
  limited: 'Too many open tabs',
  offline: 'Offline',
};
const LIVE_TITLES: Record<StreamStatus, string> = {
  connecting: 'Connecting to the live stream',
  live: 'New requests appear as they happen',
  reconnecting: 'The live stream dropped; retrying',
  limited: 'The server refused the live stream, usually because four tabs of this sign-in already have it open. Close one; this tab keeps retrying.',
  offline: 'Not receiving live updates; reload to see new requests',
};

// matches mirrors the server's filters for rows arriving on the stream,
// which is unfiltered.
function matches(r: FeedRow, f: Filters): boolean {
  return (
    (!f.agent.trim() || r.agent === f.agent.trim()) &&
    (!f.human.trim() || r.human === f.human.trim()) &&
    (!f.class || r.class === f.class) &&
    (!f.decision || r.decision === f.decision)
  );
}

export default function Feed() {
  const [filters, setFilters] = useState<Filters>(EMPTY);
  // Text filters apply after a pause in typing, not on every keystroke.
  const [applied, setApplied] = useState<Filters>(EMPTY);
  const [rows, setRows] = useState<Entry[] | null>(null);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  const [more, setMore] = useState(false);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [error, setError] = useState('');
  const seq = useRef(0);
  const appliedRef = useRef(applied);
  // Rows that arrive on the stream while a page is loading would be lost
  // (the page replaces the list) or duplicated; they wait here and are
  // merged into the page when it lands.
  const loading = useRef(true);
  const buffer = useRef<FeedRow[]>([]);
  const [live, setLive] = useState<StreamStatus>(streamStatus());

  useEffect(() => onStreamStatus(setLive), []);

  useEffect(() => {
    const t = setTimeout(() => setApplied(filters), filters.agent !== applied.agent || filters.human !== applied.human ? 300 : 0);
    return () => clearTimeout(t);
  }, [filters, applied]);

  useEffect(() => {
    appliedRef.current = applied;
    // seq discards a slow response to an older filter that lands after
    // the newer one's.
    const mine = ++seq.current;
    loading.current = true;
    buffer.current = [];
    get<FeedRow[]>(query(applied)).then(
      (page) => {
        if (mine !== seq.current) return;
        const got = page ?? [];
        const early = buffer.current.filter((r) => matches(r, appliedRef.current));
        loading.current = false;
        buffer.current = [];
        setRows(fold([], [...got, ...early]));
        // A full page of raw rows means there may be more, however few
        // requests they folded into.
        setMore(got.length >= PAGE);
        setFresh(new Set(early.map(keyOf)));
        setError('');
      },
      (e) => {
        if (mine !== seq.current) return;
        loading.current = false;
        setError(e instanceof Error ? e.message : 'Could not load the feed.');
      },
    );
  }, [applied]);

  useEffect(
    () =>
      subscribe('audit', (row) => {
        if (!matches(row, appliedRef.current)) return;
        if (loading.current) {
          buffer.current.push(row);
          return;
        }
        setRows((prev) => (prev === null ? prev : fold(prev, [row])));
        setFresh((prev) => new Set(prev).add(keyOf(row)));
      }),
    [],
  );

  async function loadOlder() {
    if (!rows || rows.length === 0) return;
    const oldest = minRawId(rows)!;
    const mine = seq.current;
    setLoadingOlder(true);
    try {
      const page = (await get<FeedRow[]>(query(applied, oldest))) ?? [];
      if (mine !== seq.current) return;
      setRows((prev) => fold(prev ?? [], page, Infinity));
      setMore(page.length >= PAGE);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load older requests.');
    } finally {
      setLoadingOlder(false);
    }
  }

  const set = (k: keyof Filters) => (e: { target: { value: string } }) => setFilters((f) => ({ ...f, [k]: e.target.value }));
  const filtered = Object.values(filters).some((v) => v.trim() !== '');

  return (
    <div className="page page-wide">
      <div className="page-head">
        <div>
          <h1>Live feed</h1>
          <p className="lede">Every request an agent sent through blastgate, newest first.</p>
        </div>
        <span className={`live live-${live}`} role="status" title={LIVE_TITLES[live]}>
          <span className="live-dot" aria-hidden="true" />
          {LIVE_LABELS[live]}
        </span>
      </div>

      <form className="filters" onSubmit={(e) => e.preventDefault()} role="search" aria-label="Filter the feed">
        <label className="field field-inline">
          <span>Agent</span>
          <input type="text" value={filters.agent} onChange={set('agent')} placeholder="any" spellCheck={false} />
        </label>
        <label className="field field-inline">
          <span>Human</span>
          <input type="text" value={filters.human} onChange={set('human')} placeholder="any" spellCheck={false} />
        </label>
        <label className="field field-inline">
          <span>Class</span>
          <select value={filters.class} onChange={set('class')}>
            <option value="">any</option>
            {CLASSES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </label>
        <label className="field field-inline">
          <span>Decision</span>
          <select value={filters.decision} onChange={set('decision')}>
            <option value="">any</option>
            {DECISIONS.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
        </label>
        {filtered && (
          <button type="button" className="btn btn-ghost btn-small" onClick={() => setFilters(EMPTY)}>
            Clear
          </button>
        )}
      </form>

      {error && (
        <p className="banner-error" role="alert">
          {error}
        </p>
      )}
      {rows === null && !error && <p className="loading">Loading…</p>}
      {rows !== null && rows.length === 0 && (
        <div className="empty">
          <p className="empty-title">No requests {filtered ? 'match these filters' : 'yet'}.</p>
          <p className="empty-sub">{filtered ? 'Try clearing a filter.' : 'Requests show up here as agents send them.'}</p>
        </div>
      )}

      {rows !== null && rows.length > 0 && (
        <div className="table-wrap">
          <table className="feed">
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">Human</th>
                <th scope="col">Agent</th>
                <th scope="col">Verb</th>
                <th scope="col">Resource</th>
                <th scope="col">Namespace / name</th>
                <th scope="col">Class</th>
                <th scope="col">Decision</th>
                <th scope="col">Rule</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ key, row: r, done }) => (
                // Reads are the bulk of traffic and never need attention,
                // so they are muted and the writes stand out.
                <tr key={key} className={[displayClass(r).cls === 'READ' ? 'muted' : '', fresh.has(key) ? 'fresh' : ''].join(' ').trim()}>
                  <td data-label="Time" className="time" title={r.at}>
                    {clock(r.at)}
                  </td>
                  <td data-label="Human">{r.human}</td>
                  <td data-label="Agent">{r.agent}</td>
                  <td data-label="Verb" className="verb">
                    {r.verb}
                  </td>
                  <td data-label="Resource" className="resource">
                    {/* One span: on narrow screens the cell is a flex row. */}
                    <span>
                      {r.resource}
                      {r.subresource && <span className="dim">/{r.subresource}</span>}
                    </span>
                  </td>
                  <td data-label="Target">{target(r.namespace, r.name)}</td>
                  <td data-label="Class">
                    <ClassBadge {...displayClass(r)} />
                  </td>
                  <td data-label="Decision">
                    <span>
                      <DecisionChip decision={r.decision} />
                      {/* Checked before it becomes a link: approval_id is
                          API data, and only a real id may reach the hash. */}
                      {APPROVAL_ID.test(r.approval_id) && (
                        <a className="row-link" href={`#/approvals/${r.approval_id}`} aria-label={`Approval for ${r.verb} ${r.name}`}>
                          approval
                        </a>
                      )}
                    </span>
                  </td>
                  <td data-label="Rule">
                    <code className="rule">{r.rule}</code>
                  </td>
                  <td data-label="Status" className="status" title={r.outcome}>
                    {!done ? <span className="dim">in flight</span> : r.status ? r.status : <span className="dim">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {more && (
        <div className="more">
          <button type="button" className="btn btn-secondary" onClick={loadOlder} disabled={loadingOlder}>
            {loadingOlder ? 'Loading…' : 'Load older'}
          </button>
        </div>
      )}
    </div>
  );
}
