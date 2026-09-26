import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import { get, subscribe, type BypassRow, type FeedRow } from '../api';
import Button from '../components/Button';
import EmptyState from '../components/EmptyState';
import NewItemsPill from '../components/NewItemsPill';
import Tag from '../components/Tag';
import { announce } from '../components/Shell';
import { useListKeys } from '../hooks/useListKeys';
import { describe } from '../lib/describe';
import { displayClass, fold, keyOf, MAX_ROWS, minRawId, outcomeOf, type Entry } from '../lib/feedModel';
import { clock, plural } from '../lib/format';
import type { Tone } from '../lib/friction';
import { DUR } from '../motion';
import { APPROVAL_ID, navigate } from '../router';

const PAGE = 50;

type Filters = { agent: string; human: string };
const EMPTY: Filters = { agent: '', human: '' };

type Outcome = ReturnType<typeof outcomeOf>;
type Chip = 'All' | 'Waiting' | 'Denied' | 'Allowed';
const CHIPS: Chip[] = ['All', 'Waiting', 'Denied', 'Allowed'];

// Neutral is not a Tag tone: an allowed or running request needs no
// attention, so it gets no colour and no glyph, only its word.
const TONES: Record<Outcome, Tone | 'neutral'> = {
  Allowed: 'neutral',
  'In flight': 'neutral',
  Waiting: 'caution',
  Interrupted: 'caution',
  Denied: 'danger',
  Failed: 'danger',
};

function query(f: Filters, before?: number): string {
  const p = new URLSearchParams({ limit: String(PAGE) });
  if (before !== undefined) p.set('before', String(before));
  for (const k of ['agent', 'human'] as const) {
    const v = f[k].trim();
    if (v) p.set(k, v);
  }
  return `/api/feed?${p.toString()}`;
}

// matches mirrors the server's filters for rows arriving on the stream,
// which is unfiltered.
function matches(r: FeedRow, f: Filters): boolean {
  return (!f.agent.trim() || r.agent === f.agent.trim()) && (!f.human.trim() || r.human === f.human.trim());
}

function shows(e: Entry, chip: Chip): boolean {
  return chip === 'All' || outcomeOf(e) === chip;
}

// countNew: requests the pill would add, as the reader would see them.
// The held rows are folded into the list first, so a held row of a
// request that is on screen but hidden by the chip counts once it would
// show, and one that is already showing never counts.
function countNew(rows: Entry[] | null, pending: FeedRow[], chip: Chip): number {
  if (pending.length === 0 || rows === null) return 0;
  const showing = new Set(rows.filter((e) => shows(e, chip)).map((e) => e.key));
  const touched = new Set(pending.map(keyOf));
  return fold(rows, pending, Infinity).filter((e) => touched.has(e.key) && !showing.has(e.key) && shows(e, chip)).length;
}

// The live summary is spoken at most this often. The list itself is not
// a live region: read node by node, a burst of rows or a page of older
// ones would talk over everything else (spec §8).
export const SUMMARY_MS = 3000;
// How long the summary stays empty before the same words come back:
// long enough for a screen reader to notice it changed.
export const REFILL_MS = 100;

function summary(inserted: number, held: number): string {
  const parts: string[] = [];
  if (inserted > 0) parts.push(`${inserted} new ${plural(inserted, 'request')}`);
  if (held > 0) parts.push(inserted > 0 ? `${held} more waiting above the list` : `${held} new ${plural(held, 'request')} waiting above the list`);
  return parts.join('. ');
}

// The outside-changes banner is spoken once per page load. It stays on
// screen every time Activity opens, but an alert said on every visit is
// one an approver learns to talk over.
let outsideAnnounced = false;

// resetOutsideNotice lets tests start each case as a fresh session.
export function resetOutsideNotice() {
  outsideAnnounced = false;
}

function OutsideBanner() {
  const [count, setCount] = useState(0);
  useEffect(() => {
    let live = true;
    get<BypassRow[]>('/api/bypass?since_hours=24&limit=500').then(
      (rows) => {
        if (live) setCount((rows ?? []).length);
      },
      // The banner is a pointer to another page; if it cannot load, the
      // feed below it still can, and the Outside page shows its own error.
      () => {},
    );
    return () => {
      live = false;
    };
  }, []);
  const title = count === 1 ? '1 change was made without going through blastgate' : `${count} changes were made without going through blastgate`;
  useEffect(() => {
    if (count === 0 || outsideAnnounced) return;
    outsideAnnounced = true;
    announce(title);
  }, [count, title]);
  if (count === 0) return null;
  return (
    <section className="activity-banner" aria-labelledby="activity-banner-title">
      <div className="activity-banner-text">
        <p id="activity-banner-title" className="activity-banner-title">
          {title}
        </p>
        <p className="activity-banner-sub">Someone used their own credentials. Review them.</p>
      </div>
      <a className="activity-banner-link" href="#/activity/outside">
        Review changes
      </a>
    </section>
  );
}

// Sentence puts the identifier in mono inside describe()'s sentence.
// Plain lastIndexOf, no pattern: the name is untrusted text. describe
// always ends a named sentence with the name, or its literal fallback
// with namespace/name, so the last occurrence is the identifier and not
// a word that happens to contain it.
function Sentence({ sentence, target, name }: { sentence: string; target: string; name: string }) {
  const pick = target && sentence.lastIndexOf(target) >= 0 ? target : name && sentence.lastIndexOf(name) >= 0 ? name : '';
  if (!pick) return <>{sentence}</>;
  const i = sentence.lastIndexOf(pick);
  return (
    <>
      {sentence.slice(0, i)}
      <span className="mono activity-target">{pick}</span>
      {sentence.slice(i + pick.length)}
    </>
  );
}

function OutcomeWord({ outcome }: { outcome: Outcome }) {
  const tone = TONES[outcome];
  if (tone === 'neutral') return <span className="activity-outcome activity-outcome-neutral">{outcome}</span>;
  return (
    <span className="activity-outcome">
      <Tag tone={tone}>{outcome}</Tag>
    </span>
  );
}

export default function Activity() {
  const [filters, setFilters] = useState<Filters>(EMPTY);
  // Text filters apply after a pause in typing, not on every keystroke.
  const [applied, setApplied] = useState<Filters>(EMPTY);
  const [chip, setChip] = useState<Chip>('All');
  const [moreOpen, setMoreOpen] = useState(false);
  const [rows, setRows] = useState<Entry[] | null>(null);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  // Raw rows held back while someone reads the list; the pill offers them.
  const [pending, setPending] = useState<FeedRow[]>([]);
  const [paused, setPaused] = useState(false);
  const [selected, setSelected] = useState(-1);
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
  const listRef = useRef<HTMLDivElement>(null);
  const rowsRef = useRef<Entry[] | null>(null);
  const pendingRef = useRef<FeedRow[]>([]);
  const pausedRef = useRef(false);
  const pointerInside = useRef(false);
  const chipRef = useRef(chip);
  // Set inside a rows updater when the cap trims the oldest requests off
  // the bottom; an effect then offers "Load older" again to reach them.
  const trimmed = useRef(false);
  const [said, setSaid] = useState('');
  const saidRef = useRef('');
  const inserted = useRef(0);
  const sayTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const refillTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const tintTimers = useRef(new Set<ReturnType<typeof setTimeout>>());
  rowsRef.current = rows;
  chipRef.current = chip;

  useEffect(() => {
    const timers = tintTimers.current;
    return () => {
      clearTimeout(sayTimer.current);
      clearTimeout(refillTimer.current);
      timers.forEach(clearTimeout);
    };
  }, []);

  useEffect(() => {
    if (!trimmed.current) return;
    trimmed.current = false;
    setMore(true);
  }, [rows]);

  // foldLive folds live rows under the cap, noting when it trims.
  const foldLive = (prev: Entry[], add: FeedRow[]): Entry[] => {
    const all = fold(prev, add, Infinity);
    if (all.length <= MAX_ROWS) return all;
    trimmed.current = true;
    return all.slice(0, MAX_ROWS);
  };

  // say schedules one summary for everything that happened in the next
  // SUMMARY_MS: what went in, and what is waiting behind the pill then.
  // Only the stream calls it; Load older and the chips never do.
  const say = () => {
    if (sayTimer.current !== undefined) return;
    sayTimer.current = setTimeout(() => {
      sayTimer.current = undefined;
      const text = summary(inserted.current, countNew(rowsRef.current, pendingRef.current, chipRef.current));
      inserted.current = 0;
      if (!text) return;
      clearTimeout(refillTimer.current);
      // A screen reader speaks a change, not a text: "1 new request"
      // twice running would be heard once. The same words again are
      // emptied first and put back a moment later.
      if (text === saidRef.current) {
        saidRef.current = '';
        setSaid('');
        refillTimer.current = setTimeout(() => {
          saidRef.current = text;
          setSaid(text);
        }, REFILL_MS);
        return;
      }
      saidRef.current = text;
      setSaid(text);
    }, SUMMARY_MS);
  };

  // tint marks requests as just arrived for the length of the tint, then
  // forgets them: a key left in the set would replay the tint every time
  // a chip change remounts its row.
  const tint = (keys: string[]) => {
    if (keys.length === 0) return;
    setFresh((prev) => new Set([...prev, ...keys]));
    const t = setTimeout(() => {
      tintTimers.current.delete(t);
      setFresh((prev) => {
        const next = new Set(prev);
        keys.forEach((k) => next.delete(k));
        return next;
      });
    }, DUR.tint * 1000);
    tintTimers.current.add(t);
  };

  // reading: is someone looking at the list right now? Scrolled down,
  // focus or pointer in it, or paused. Read from the DOM at the moment a
  // row arrives, so it can never be a render behind.
  const reading = () => {
    const list = listRef.current;
    if (pausedRef.current || pointerInside.current) return true;
    if (!list) return false;
    return list.scrollTop > 0 || list.contains(document.activeElement);
  };

  // flush folds the held rows (and any new ones) into the list and tints
  // the requests that were not on screen before.
  const flush = (extra: FeedRow[]) => {
    const all = [...pendingRef.current, ...extra];
    pendingRef.current = [];
    setPending([]);
    if (all.length === 0) return;
    const before = new Set((rowsRef.current ?? []).map((e) => e.key));
    const added = [...new Set(all.map(keyOf))].filter((k) => !before.has(k));
    setRows((prev) => (prev === null ? prev : foldLive(prev, all)));
    tint(added);
    if (added.length > 0) {
      inserted.current += added.length;
      say();
    }
  };

  useEffect(() => {
    const t = setTimeout(() => setApplied(filters), 300);
    return () => clearTimeout(t);
  }, [filters]);

  useEffect(() => {
    appliedRef.current = applied;
    // seq discards a slow response to an older filter that lands after
    // the newer one's.
    const mine = ++seq.current;
    loading.current = true;
    buffer.current = [];
    pendingRef.current = [];
    setPending([]);
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
        setFresh(new Set());
        tint(early.map(keyOf));
        setError('');
      },
      (e) => {
        if (mine !== seq.current) return;
        loading.current = false;
        setError(e instanceof Error ? e.message : 'Could not load activity.');
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
        if (!reading()) {
          flush([row]);
          return;
        }
        // A later row of a request already on screen (its result, or a
        // resumed stream repeating it) changes the row's words but not
        // its place, so it can land under a reader. An older row would
        // move the request down, and waits with the rest.
        // Nor may an update that shows or hides the row under the chip
        // the reader chose: that adds or removes a line mid-list.
        const key = keyOf(row);
        const shown = rowsRef.current?.find((e) => e.key === key);
        if (shown && row.id >= shown.first) {
          const after = fold([shown], [row])[0];
          if (shows(shown, chipRef.current) === shows(after, chipRef.current)) {
            setRows((prev) => (prev === null ? prev : foldLive(prev, [row])));
            return;
          }
        }
        pendingRef.current = [...pendingRef.current, row];
        setPending(pendingRef.current);
        say();
      }),
    // Subscribed once: flush and reading touch only refs and setters.
    [],
  );

  const newCount = useMemo(() => countNew(rows, pending, chip), [pending, rows, chip]);

  function showNew() {
    flush([]);
    // The pill unmounts once clicked; focus goes to the list it filled
    // rather than falling back to the page.
    if (listRef.current) {
      listRef.current.scrollTop = 0;
      listRef.current.focus();
    }
  }

  function togglePause() {
    const next = !pausedRef.current;
    pausedRef.current = next;
    setPaused(next);
    // Resuming is asking for the live list: what waited comes in now,
    // unless the reader is still in the list.
    if (!next && !reading()) flush([]);
  }

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

  const visible = useMemo(() => (rows ?? []).filter((e) => shows(e, chip)), [rows, chip]);
  const linkOf = (e: Entry) => (e.row.decision === 'hold' && APPROVAL_ID.test(e.row.approval_id) ? `#/approvals/${e.row.approval_id}` : '');

  const focusRow = (i: number) => {
    setSelected(i);
    listRef.current?.querySelectorAll<HTMLElement>('.activity-row')[i]?.focus();
  };
  const keys = useListKeys({
    count: visible.length,
    index: selected,
    onMove: focusRow,
    onOpen: (i) => {
      const href = visible[i] && linkOf(visible[i]);
      if (href) navigate(href);
    },
  });

  const set = (k: keyof Filters) => (e: { target: { value: string } }) => setFilters((f) => ({ ...f, [k]: e.target.value }));
  const textFiltered = filters.agent.trim() !== '' || filters.human.trim() !== '';
  const filtered = textFiltered || chip !== 'All';
  // The tint's length comes from motion.ts, the one place timings live;
  // CSS runs it, since a background fade needs no animation library.
  const tintVar = { '--activity-tint': `${DUR.tint * 1000}ms` } as CSSProperties;

  return (
    <div className="page page-wide activity">
      <div className="activity-head">
        <h1>Activity</h1>
        <p className="activity-lede">Every request an agent sent through blastgate, newest first.</p>
      </div>

      <OutsideBanner />

      <div className="activity-controls">
        <div className="activity-chips" role="group" aria-label="Show">
          {CHIPS.map((c) => (
            <button key={c} type="button" className="activity-chip" aria-pressed={chip === c} onClick={() => setChip(c)}>
              {c}
            </button>
          ))}
        </div>
        <div className="activity-actions">
          <Button variant="quiet" aria-expanded={moreOpen} aria-controls="activity-more" onClick={() => setMoreOpen((o) => !o)}>
            More filters
          </Button>
          <Button className="activity-pause" aria-pressed={paused} onClick={togglePause}>
            Pause
          </Button>
        </div>
      </div>

      {moreOpen && (
        <form id="activity-more" className="activity-more" role="search" aria-label="Filter activity" onSubmit={(e) => e.preventDefault()}>
          <label className="activity-field">
            <span>Agent</span>
            <input type="text" value={filters.agent} onChange={set('agent')} placeholder="any" spellCheck={false} />
          </label>
          <label className="activity-field">
            <span>Human</span>
            <input type="text" value={filters.human} onChange={set('human')} placeholder="any" spellCheck={false} />
          </label>
          {textFiltered && (
            <Button variant="quiet" onClick={() => setFilters(EMPTY)}>
              Clear
            </Button>
          )}
        </form>
      )}

      {paused && <p className="activity-paused">Paused. New requests wait above the list until you resume.</p>}

      {error && (
        <p className="activity-error" role="alert">
          {error}
        </p>
      )}

      <div className="activity-pill-slot">
        <NewItemsPill count={newCount} onShow={showNew} />
      </div>

      {rows === null && !error && (
        <p className="activity-loading" aria-busy="true">
          Loading…
        </p>
      )}
      {rows !== null && visible.length === 0 && (
        <EmptyState
          title={filtered ? 'No requests match these filters.' : 'No requests yet.'}
          sub={filtered ? 'Choose All, or clear the text filters.' : 'Requests show up here as agents send them.'}
        />
      )}

      <p className="visually-hidden activity-summary" role="status">
        {said}
      </p>

      {/* Mounted even when empty, so a reader's scroll, focus and pointer
          are tracked on one element for the life of the page. */}
      <div
        ref={listRef}
        role="log"
        aria-live="off"
        aria-label="Requests"
        className="activity-list"
        hidden={rows === null || visible.length === 0}
        style={tintVar}
        onPointerEnter={() => (pointerInside.current = true)}
        onPointerLeave={() => (pointerInside.current = false)}
        {...keys}
      >
        {visible.map((e, i) => {
          const r = e.row;
          const d = describe(r);
          const href = linkOf(e);
          const cls = ['activity-row', displayClass(r).cls === 'READ' ? 'activity-row-read' : '', fresh.has(e.key) ? 'activity-row-fresh' : ''].filter(Boolean).join(' ');
          return (
            <div key={e.key} className={cls} tabIndex={-1} onFocus={() => setSelected(i)}>
              <time className="activity-when" dateTime={r.at} title={r.at}>
                {clock(r.at)}
              </time>
              <div className="activity-what">
                {/* Checked before it becomes a link: approval_id is API
                    data, and only a real id may reach the hash. */}
                {href ? (
                  <a className="activity-sentence" href={href}>
                    <Sentence sentence={d.sentence} target={d.target} name={r.name} />
                  </a>
                ) : (
                  <span className="activity-sentence">
                    <Sentence sentence={d.sentence} target={d.target} name={r.name} />
                  </span>
                )}
                <span className="activity-who">
                  {r.human} via {r.agent}
                  {r.namespace && !d.sentence.includes(r.namespace) && (
                    <>
                      {' · '}
                      <span className="mono">{r.namespace}</span>
                    </>
                  )}
                </span>
              </div>
              <OutcomeWord outcome={outcomeOf(e)} />
            </div>
          );
        })}
      </div>

      {more && rows !== null && rows.length > 0 && (
        <div className="activity-more-rows">
          <Button onClick={loadOlder} disabled={loadingOlder}>
            {loadingOlder ? 'Loading…' : 'Load older'}
          </Button>
        </div>
      )}
    </div>
  );
}
