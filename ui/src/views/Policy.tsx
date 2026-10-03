import { useEffect, useId, useRef, useState } from 'react';
import { ApiError, get, post, type ReplayResult, type RuleStat, type RuleStats } from '../api';
import { describe } from '../lib/describe';
import Sentence from '../components/Sentence';
import Button from '../components/Button';
import { announce } from '../components/Shell';
import Tag from '../components/Tag';

type Loaded = { source: string; text: string };

// The server refuses anything outside these; checking here says why in
// words instead of showing a bare 400.
const MIN_HOURS = 1;
const MAX_HOURS = 720;
const MAX_POLICY_BYTES = 64 * 1024;
const HOURS_PRESETS = [1, 6, 24, 168, 720];

function parseHours(v: string): number | null {
  if (!/^\d+$/.test(v.trim())) return null;
  const n = Number(v.trim());
  return n >= MIN_HOURS && n <= MAX_HOURS ? n : null;
}

// The words a decision reads as, in plain language (spec §4/§5). A value
// this UI has not been taught yet still shows, raw, rather than vanish
// behind an unmatched case.
const DECISION_WORDS: Record<string, string> = { hold: 'Held', allow: 'Allowed', deny: 'Denied' };
function decisionWord(d: string): string {
  return Object.hasOwn(DECISION_WORDS, d) ? DECISION_WORDS[d] : d;
}

// A rule people approve nearly every time is a candidate for allow. Ten
// holds is the least that says so: at nine, one more denial moves the
// rate a long way.
const STAMP_MIN_HELD = 10;
const STAMP_MIN_RATE = 0.95;

export function rubberStamped(r: Pick<RuleStat, 'held' | 'approve_rate'>): boolean {
  return r.held >= STAMP_MIN_HELD && typeof r.approve_rate === 'number' && r.approve_rate >= STAMP_MIN_RATE;
}

// rate reads as a whole percentage; no decision is a dash, never 0%.
function rate(v: number | null): string {
  return typeof v === 'number' && Number.isFinite(v) ? `${Math.round(v * 100)}%` : '—';
}

// count shows a count as text, and anything that is not one as a dash: a
// value from the server is rendered, never trusted to be renderable.
function count(v: unknown): string {
  return typeof v === 'number' && Number.isFinite(v) ? String(v) : '—';
}

// window words the stats window: "7 days" for 168 hours, else hours.
function windowText(hours: number): string {
  if (hours % 24 === 0) {
    const d = hours / 24;
    return d === 1 ? 'day' : `${d} days`;
  }
  return hours === 1 ? 'hour' : `${hours} hours`;
}

export default function Policy() {
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [loadError, setLoadError] = useState('');
  const [candidate, setCandidate] = useState('');
  const [hours, setHours] = useState('24');
  const [formError, setFormError] = useState('');
  const [parseError, setParseError] = useState('');
  const [error, setError] = useState('');
  const [result, setResult] = useState<ReplayResult | null>(null);
  const [busy, setBusy] = useState(false);
  // Prefilled once, and only if the operator has not started typing: a
  // late GET answer must never overwrite an edit already in progress.
  const touched = useRef(false);

  useEffect(() => {
    get<Loaded>('/api/policy').then(
      (p) => {
        setLoaded(p);
        if (!touched.current) setCandidate(p.text);
      },
      (e) => setLoadError(e instanceof Error ? e.message : 'Could not load the policy.'),
    );
  }, []);

  async function replay() {
    const since = parseHours(hours);
    if (since === null) {
      setFormError(`Enter a whole number of hours from ${MIN_HOURS} to ${MAX_HOURS}.`);
      return;
    }
    if (candidate.trim() === '') {
      setFormError('Paste a candidate policy first.');
      return;
    }
    if (new TextEncoder().encode(candidate).length > MAX_POLICY_BYTES) {
      setFormError('The candidate is larger than 64 KiB, the most blastgate accepts.');
      return;
    }
    setFormError('');
    setParseError('');
    setError('');
    setResult(null);
    setBusy(true);
    try {
      const r = await post<ReplayResult>('/api/policy/replay', { policy: candidate, since_hours: since });
      setResult(r);
      // Said once through the shell's one alert region, so a screen reader
      // hears the count when a replay finishes rather than only finding it.
      if (r && typeof r === 'object') announce(`${r.changed} of ${r.evaluated} decisions would change`);
    } catch (e) {
      // 400: the candidate did not parse. The parser's own message says
      // exactly where, so it is shown exactly, never paraphrased. 429:
      // another replay is already running, which is about the request,
      // not the candidate, so it gets a fixed sentence instead of
      // whatever text the server happened to send back.
      if (e instanceof ApiError && e.status === 400) setParseError(e.message);
      else if (e instanceof ApiError && e.status === 429) setError('A replay is already running; try again when it finishes.');
      else setError(e instanceof Error ? e.message : 'The replay did not run.');
    } finally {
      setBusy(false);
    }
  }

  const n = parseHours(hours);
  const bytes = new TextEncoder().encode(candidate).length;
  const overLimit = bytes > MAX_POLICY_BYTES;

  return (
    <div className="page page-wide policy-page">
      <header className="page-head policy-head">
        <h1 className="page-title">Policy</h1>
        <p className="page-lede policy-lede">Try a change on the past: see which decisions would have gone the other way. Nothing is applied from here.</p>
      </header>

      {loadError && (
        <p className="policy-banner-error" role="alert">
          {loadError}
        </p>
      )}

      {loaded && (
        <details className="policy-disclosure">
          <summary>
            Loaded policy · <code className="mono">{loaded.source}</code>
          </summary>
          <pre className="mono policy-loaded-text" aria-label="Loaded policy">
            {loaded.text}
          </pre>
        </details>
      )}

      <Stats />

      {/* Try a policy sits beside its own result at 900px and wider (the
          approved mockup); below that the two stack, and neither ever
          forces the page itself to scroll sideways at 360px. */}
      <div className="policy-grid">
        <section className="policy-try">
          <h2>Try a policy</h2>
          <form
            className="policy-form"
            // Our own message says what is wrong and where; the browser's
            // bubble would block the submit without saying the range.
            noValidate
            onSubmit={(e) => {
              e.preventDefault();
              if (!busy) void replay();
            }}
          >
            <span className={`policy-counter${overLimit ? ' policy-counter-danger' : ''}`}>
              {bytes.toLocaleString()} / {MAX_POLICY_BYTES.toLocaleString()} bytes
            </span>
            <label className="policy-field">
              <span>Candidate policy</span>
              <textarea
                className="mono policy-textarea"
                value={candidate}
                onChange={(e) => {
                  touched.current = true;
                  setCandidate(e.target.value);
                }}
                spellCheck={false}
                rows={14}
              />
            </label>
            <div className="policy-controls">
              <label className="policy-hours-field">
                <span>Hours of history</span>
                <input
                  className="policy-hours-input mono"
                  type="number"
                  inputMode="numeric"
                  list="policy-hours-presets"
                  min={MIN_HOURS}
                  max={MAX_HOURS}
                  step={1}
                  value={hours}
                  onChange={(e) => setHours(e.target.value)}
                />
                <datalist id="policy-hours-presets">
                  {HOURS_PRESETS.map((h) => (
                    <option key={h} value={h} />
                  ))}
                </datalist>
              </label>
              <Button type="submit" disabled={busy}>
                {busy ? 'Replaying…' : `Replay over the last ${n ?? 'N'} ${n === 1 ? 'hour' : 'hours'}`}
              </Button>
            </div>
            {formError && (
              <p className="policy-form-error" role="alert">
                {formError}
              </p>
            )}
          </form>
        </section>

        <div className="policy-results">
          {parseError && (
            <section className="policy-error" role="alert">
              <h2>The candidate does not load</h2>
              <pre className="mono policy-error-text" aria-label="Policy error">
                {parseError}
              </pre>
            </section>
          )}
          {error && (
            <p className="policy-banner-error" role="alert">
              {error}
            </p>
          )}

          {result && <Result r={result} />}
        </div>
      </div>
    </div>
  );
}

// Stats is "How each rule is used": for each rule that held something,
// how those requests ended. A rule approved almost every time is flagged
// as one to consider allowing; nothing is changed from here.
function Stats() {
  const titleId = useId();
  const [stats, setStats] = useState<RuleStats | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    get<RuleStats>('/api/policy/stats').then(
      (r) => {
        // A body without a rules list is no stats at all, never an empty table.
        if (r && typeof r === 'object' && Array.isArray(r.rules)) setStats(r);
        else setError('the server sent something that is not rule statistics');
      },
      (e) => setError(e instanceof Error ? e.message : 'request failed'),
    );
  }, []);

  const hours = stats && typeof stats.since_hours === 'number' && stats.since_hours > 0 ? stats.since_hours : 168;
  const rules = (stats?.rules ?? []).filter((r): r is RuleStat => !!r && typeof r === 'object');

  return (
    <section className="policy-stats" aria-labelledby={titleId}>
      <h2 id={titleId}>How each rule is used</h2>
      {error ? (
        <p className="policy-note">Couldn't load how each rule is used: {error}</p>
      ) : stats === null ? (
        <p className="policy-note" aria-busy="true">
          Loading…
        </p>
      ) : (
        <>
          <p className="policy-note">Requests each rule held in the last {windowText(hours)}, and how they ended.</p>
          {rules.length === 0 ? (
            <p className="policy-empty">No rule held a request in this time.</p>
          ) : (
            <table className="policy-stats-table">
              <thead>
                <tr>
                  <th scope="col">Rule</th>
                  <th scope="col">Held</th>
                  <th scope="col">Approved</th>
                  <th scope="col">Denied</th>
                  <th scope="col">Expired</th>
                  <th scope="col">Rate</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r, i) => (
                  <tr key={`${r.rule}-${i}`}>
                    <td data-label="Rule">
                      <span className="mono policy-stats-rule">{typeof r.rule === 'string' ? r.rule : ''}</span>
                      {rubberStamped(r) && (
                        <span className="policy-stats-flag">
                          <Tag tone="caution">Almost always approved — consider allowing it</Tag>
                        </span>
                      )}
                    </td>
                    <td data-label="Held">{count(r.held)}</td>
                    <td data-label="Approved">{count(r.approved)}</td>
                    <td data-label="Denied">{count(r.denied)}</td>
                    <td data-label="Expired">{count(r.expired)}</td>
                    <td data-label="Rate">{rate(r.approve_rate)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </section>
  );
}

function Result({ r }: { r: ReplayResult }) {
  const changes = r.changes ?? [];
  return (
    <section className="policy-result" role="region" aria-label="Replay result">
      {/* A status, so the count is heard when a replay finishes: the
          button only changes back from "Replaying…" otherwise. */}
      <p className="policy-result-count" role="status">
        <strong>
          {r.changed} of {r.evaluated}
        </strong>{' '}
        decisions would change
      </p>
      {r.truncated && <p className="policy-note">Only the most recent {r.evaluated} decisions in this window were replayed.</p>}
      {r.changed === 0 ? (
        <p className="policy-empty">No request would have been decided differently.</p>
      ) : (
        <ul className="policy-changes">
          {changes.map((c, i) => {
            const d = describe({ verb: c.verb, resource: c.resource, namespace: c.namespace, name: c.name });
            return (
              <li key={`${c.request_id}-${i}`} className="policy-change">
                <p className="policy-change-sentence">
                  <Sentence sentence={d.sentence} target={d.target} name={c.name} identClass="policy-change-target" />
                </p>
                <p className="policy-change-decision">{`${decisionWord(c.decision_before)} → ${decisionWord(c.decision_after)}`}</p>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
