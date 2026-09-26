import { useEffect, useRef, useState } from 'react';
import { ApiError, get, post, type ReplayResult } from '../api';
import { describe } from '../lib/describe';
import Sentence from '../components/Sentence';
import Button from '../components/Button';

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
const DECISION_WORDS: Record<string, string> = { hold: 'Waited for approval', allow: 'Allowed', deny: 'Denied' };
function decisionWord(d: string): string {
  return Object.hasOwn(DECISION_WORDS, d) ? DECISION_WORDS[d] : d;
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
      setResult(await post<ReplayResult>('/api/policy/replay', { policy: candidate, since_hours: since }));
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

function Result({ r }: { r: ReplayResult }) {
  const changes = r.changes ?? [];
  return (
    <section className="policy-result" role="region" aria-label="Replay result">
      <p className="policy-result-count">
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
