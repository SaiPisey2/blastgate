import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { get, subscribe, type ApprovalDetail, type ApprovalSummary } from '../api';
import DecisionPanel, { GONE_TEXT, type Outcome } from '../components/DecisionPanel';
import EmptyState from '../components/EmptyState';
import { announce } from '../components/Shell';
import { GLYPH } from '../components/Tag';
import Button from '../components/Button';
import { useListKeys } from '../hooks/useListKeys';
import { useMediaQuery } from '../hooks/useMediaQuery';
import { describe } from '../lib/describe';
import { ago, hhmm, useNow } from '../lib/format';
import { frictionOf } from '../lib/friction';
import { AnimatePresence, DUR, EASE, m, useIsPresent } from '../motion';

const PENDING = '/api/approvals?status=pending';
export const WIDE = '(min-width: 900px)';

const NOTES: Record<Outcome, string> = {
  approved: 'Approved. The agent can go ahead.',
  denied: 'Denied. The agent was refused.',
  gone: 'That request was already decided or has expired.',
};

// oldestFirst orders the list by when each hold was made, then by id so
// equal times keep one order. The server already sends them this way; the
// sort keeps the page right if it ever does not, since the oldest is the
// one closest to expiring. A time that does not parse sorts first rather
// than hiding at the bottom.
export function oldestFirst(a: ApprovalSummary, b: ApprovalSummary): number {
  const ta = Date.parse(a.created);
  const tb = Date.parse(b.created);
  const ka = Number.isNaN(ta) ? -Infinity : ta;
  const kb = Number.isNaN(tb) ? -Infinity : tb;
  if (ka !== kb) return ka < kb ? -1 : 1;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

// When this tab last saw its approver decide something, for the empty
// state. Module state, not storage: it lasts as long as the page, and a
// reload or another tab starts without it.
let lastDecision: Date | null = null;

// resetLastDecision forgets it; tests call it so one cannot leak into the next.
export function resetLastDecision() {
  lastDecision = null;
}


function sentenceOf(s: ApprovalSummary): string {
  return describe({ verb: s.verb, resource: s.resource, namespace: s.namespace, name: s.name }).sentence;
}

function ageOf(s: ApprovalSummary, now: number): string {
  const t = Date.parse(s.created);
  return ago(Number.isNaN(t) ? s.age_seconds : (now - t) / 1000);
}

// me: the signed-in approver's name, for the panel's self-approval guard.
export default function Waiting({ me = '' }: { me?: string }) {
  const wide = useMediaQuery(WIDE);
  const now = useNow();
  const listId = useId();
  const titleId = useId();
  const [items, setItems] = useState<ApprovalSummary[] | null>(null);
  const [error, setError] = useState('');
  const [details, setDetails] = useState<Record<string, ApprovalDetail>>({});
  const [detailErrors, setDetailErrors] = useState<Record<string, string>>({});
  // selected: the request on screen. Set on the first list and changed
  // only by the approver or by their own decision, never by the list
  // changing under them. On a narrow screen it also moves on when the
  // request leaves the list; on a wide one it stays, marked gone.
  const [selected, setSelected] = useState<string | null>(null);
  const [note, setNote] = useState('');
  // keyed: the selection last moved by key. A row the selection leaves
  // while the pointer rests on it turns hovered, and the hover rule's
  // colour fade would play: a keyboard move must stay instant (spec §7).
  // The pointer moving again hands the list back to hover.
  const [keyed, setKeyed] = useState(false);

  // The last summary seen for each id, so a request that leaves the list
  // while it is being read can still say what it was.
  const known = useRef(new Map<string, ApprovalSummary>());
  // Ids already announced, or already waiting when the page opened.
  const heard = useRef(new Set<string>());
  // Decided here: a list fetched before the decision landed must not put
  // the request back as if it were still waiting.
  const decided = useRef(new Set<string>());
  const firstLoad = useRef(true);
  const seq = useRef(0);
  const fetching = useRef(new Set<string>());
  const focusNext = useRef(false);
  const panelRef = useRef<HTMLElement>(null);
  const titleRef = useRef<HTMLHeadingElement>(null);
  // live: the list as last committed. onDecided reads this, never the
  // rows its own render captured: a reload can land while the decision
  // is in flight, and rebuilding from the older rows would hide what it
  // brought (already heard, so never announced) or bring back what it
  // dropped.
  const live = useRef<ApprovalSummary[]>([]);
  const wideRef = useRef(wide);
  wideRef.current = wide;

  const commit = useCallback((rows: ApprovalSummary[]) => {
    live.current = rows;
    setItems(rows);
  }, []);

  const load = useCallback(async () => {
    // Only the newest load may land: a slow answer to an earlier one is
    // older than the stream event that started the next, and applying it
    // would drop a request that is really waiting.
    const mine = ++seq.current;
    try {
      const list = await get<ApprovalSummary[]>(PENDING);
      if (mine !== seq.current) return;
      // The server lists pending only; anything else is not ours to show.
      const rows = (Array.isArray(list) ? list : []).filter((r) => r && r.status === 'pending' && !decided.current.has(r.id)).sort(oldestFirst);
      const fresh: ApprovalSummary[] = [];
      for (const r of rows) {
        known.current.set(r.id, r);
        if (heard.current.has(r.id)) continue;
        heard.current.add(r.id);
        fresh.push(r);
      }
      // One announcement per reload: each announce() replaces the one
      // before it, so a second call would silence the first.
      if (!firstLoad.current && fresh.length === 1) announce(`New request waiting: ${sentenceOf(fresh[0])}`);
      if (!firstLoad.current && fresh.length > 1) announce(`${fresh.length} new requests waiting`);
      firstLoad.current = false;
      commit(rows);
      setError('');
      setSelected((prev) => {
        if (prev && rows.some((r) => r.id === prev)) return prev;
        // Wide keeps a vanished choice on screen, marked gone.
        if (prev && wideRef.current) return prev;
        return rows[0]?.id ?? null;
      });
    } catch (e) {
      if (mine !== seq.current) return;
      setError(e instanceof Error ? e.message : 'Could not load what is waiting.');
    }
  }, [commit]);

  useEffect(() => {
    // Subscribed before the first fetch: an event that lands while it is
    // in flight starts a newer load instead of being missed.
    const off = subscribe('approvals', () => void load());
    void load();
    return off;
  }, [load]);

  const fetchDetail = useCallback((id: string) => {
    fetching.current.add(id);
    setDetailErrors((prev) => {
      const { [id]: _drop, ...rest } = prev;
      return rest;
    });
    get<ApprovalDetail>(`/api/approvals/${encodeURIComponent(id)}`).then(
      (d) => {
        fetching.current.delete(id);
        // An answer about some other request is no answer: the panel
        // would ignore it and leave Approve disabled with nothing to
        // press. As an error it gets a Retry.
        if (!d || d.id !== id) {
          setDetailErrors((prev) => ({ ...prev, [id]: 'the server answered for a different request' }));
          return;
        }
        setDetails((prev) => ({ ...prev, [id]: d }));
      },
      // The panel shows this with a retry; Approve stays disabled
      // meanwhile, because approving without the impact is approving blind.
      (e) => {
        fetching.current.delete(id);
        setDetailErrors((prev) => ({ ...prev, [id]: e instanceof Error ? e.message : 'request failed' }));
      },
    );
  }, []);

  const rows = items ?? [];
  // Narrow falls back to the oldest only until the next list pins it.
  const current = wide ? rows.find((r) => r.id === selected) : (rows.find((r) => r.id === selected) ?? rows[0]);
  // Wide only: the chosen request left the list (decided elsewhere, or
  // expired) while it was open. It stays on screen, marked gone, until
  // the approver picks another. Swapping the next one in under them could
  // turn a half-typed confirmation into one for a different request.
  const vanished = wide && !current && selected ? known.current.get(selected) : undefined;
  const targetId = current?.id;

  useEffect(() => {
    if (!targetId || details[targetId] || detailErrors[targetId] || fetching.current.has(targetId)) return;
    fetchDetail(targetId);
  }, [targetId, details, detailErrors, fetchDetail]);

  // After a decision, focus goes to the next request's question, so a
  // keyboard or screen reader user lands on what to read next rather than
  // on the page's first control. With nothing left, on the page title.
  useEffect(() => {
    if (!focusNext.current || items === null) return;
    const h = panelRef.current?.querySelector<HTMLElement>('h2');
    const target = h ?? (rows.length === 0 ? titleRef.current : null);
    if (!target) return;
    focusNext.current = false;
    // Both headings carry tabIndex -1 themselves: they hold focus without
    // becoming tab stops.
    target.focus();
  });

  function onDecided(id: string, outcome: Outcome) {
    decided.current.add(id);
    const list = live.current;
    const i = list.findIndex((r) => r.id === id);
    const rest = list.filter((r) => r.id !== id);
    const next = i < 0 ? rest[0] : (rest[i] ?? rest[i - 1]);
    commit(rest);
    if (outcome !== 'gone') lastDecision = new Date();
    setSelected(next ? next.id : null);
    setNote(NOTES[outcome]);
    focusNext.current = true;
  }

  function choose(id: string) {
    if (id === selected) return;
    setSelected(id);
    setNote('');
  }

  const selectedIndex = rows.findIndex((r) => r.id === selected);
  const keys = useListKeys({
    count: rows.length,
    index: selectedIndex,
    onMove: (i) => {
      setKeyed(true);
      choose(rows[i].id);
    },
    onOpen: () => {
      panelRef.current?.querySelector<HTMLElement>('h2')?.focus();
    },
  });

  const panel = current ? (
    <DecisionPanel
      summary={current}
      detail={details[current.id]}
      detailError={detailErrors[current.id]}
      me={me}
      onRetry={() => fetchDetail(current.id)}
      onDecided={onDecided}
      position={wide ? undefined : { index: rows.indexOf(current) + 1, total: rows.length }}
    />
  ) : vanished ? (
    <Gone summary={vanished} />
  ) : null;

  return (
    <div className="page page-wide waiting">
      <h1 ref={titleRef} id={titleId} className={wide ? 'page-title waiting-title' : 'page-title waiting-title visually-hidden'} tabIndex={-1}>
        Waiting for you
      </h1>

      {note && (
        <p className="waiting-note" role="status">
          {note}
        </p>
      )}
      {error && (
        <div className="waiting-error" role="alert">
          <span>Couldn't load what is waiting: {error}</span>
          <Button variant="quiet" onClick={() => void load()}>
            Retry
          </Button>
        </div>
      )}

      {items === null && !error && (
        <p className="waiting-loading" aria-busy="true">
          Loading…
        </p>
      )}

      {items !== null && rows.length === 0 && (
        <EmptyState
          title="Nothing is waiting for you."
          sub={
            lastDecision
              ? `Last decision at ${hhmm(lastDecision)}. Held requests appear here the moment an agent makes one.`
              : 'Held requests appear here the moment an agent makes one.'
          }
        />
      )}

      {rows.length > 0 &&
        (wide ? (
          <div className="waiting-split">
            <ul
              className={keyed ? 'waiting-list is-keyboard' : 'waiting-list'}
              onPointerMove={keyed ? () => setKeyed(false) : undefined}
              role="listbox"
              aria-labelledby={titleId}
              aria-activedescendant={selectedIndex >= 0 ? `${listId}-${rows[selectedIndex].id}` : undefined}
              {...keys}
            >
              <AnimatePresence mode="sync" initial={false}>
                {rows.map((s) => (
                  <Row key={s.id} id={`${listId}-${s.id}`} s={s} detail={details[s.id]} now={now} selected={s.id === selected} onChoose={() => choose(s.id)} />
                ))}
              </AnimatePresence>
            </ul>
            <section className="waiting-panel" ref={panelRef} aria-label="Chosen request">
              {panel}
            </section>
          </div>
        ) : (
          <section className="waiting-one" ref={panelRef} aria-label="Next request">
            {panel}
          </section>
        ))}
    </div>
  );
}

type RowProps = { id: string; s: ApprovalSummary; detail?: ApprovalDetail; now: number; selected: boolean; onChoose: () => void };

// Row is one waiting request in the wide list. It enters over DUR.enter
// when it arrives and leaves within DUR.exit when decided; on its way out
// it is hidden from assistive tech and takes no clicks.
function Row({ id, s, detail, now, selected, onChoose }: RowProps) {
  const present = useIsPresent();
  const impact = detail && detail.id === s.id ? detail.impact : undefined;
  const f = frictionOf(s, impact);
  return (
    <m.li
      id={id}
      role="option"
      aria-selected={selected}
      aria-hidden={present ? undefined : true}
      className={selected ? 'waiting-row is-selected' : 'waiting-row'}
      onClick={present ? onChoose : undefined}
      initial={{ opacity: 0, y: -6 }}
      animate={{ opacity: 1, y: 0, transition: { duration: DUR.enter, ease: EASE } }}
      exit={{ opacity: 0, transition: { duration: DUR.exit, ease: EASE } }}
    >
      <span className={`waiting-dot tone-${f.tone}`} aria-hidden="true">
        {GLYPH[f.tone]}
      </span>
      <span className="waiting-row-text">
        <span className="waiting-sentence waiting-wrap">{sentenceOf(s)}</span>
        <span className="visually-hidden">{`, ${f.tag}, `}</span>
        <span className="waiting-meta waiting-wrap">
          {s.human || 'Unknown'} · {ageOf(s, now)}
        </span>
      </span>
    </m.li>
  );
}

// Gone stands in for the panel of a request that left the list while it
// was open: what it was, that it is no longer waiting, and no controls.
function Gone({ summary: s }: { summary: ApprovalSummary }) {
  const qid = useId();
  const d = describe({ verb: s.verb, resource: s.resource, namespace: s.namespace, name: s.name });
  // As in the panel: the name at the end of the sentence is shown as the
  // full namespace/name, in mono. A suffix check, never a pattern: the
  // name is untrusted.
  let words = d.sentence;
  let ident = '';
  if (s.name && words.endsWith(s.name)) {
    words = words.slice(0, words.length - s.name.length);
    ident = d.target || s.name;
  }
  words = words.charAt(0).toLowerCase() + words.slice(1);
  return (
    <article className="decision" aria-labelledby={qid}>
      <h2 id={qid} className="decision-q" tabIndex={-1}>
        {s.agent || 'An agent'} wanted to {words}
        {ident && <span className="mono">{ident}</span>}
      </h2>
      <p className="decision-done" role="status">
        {GONE_TEXT}
      </p>
    </article>
  );
}
