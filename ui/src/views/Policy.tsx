import { useEffect, useRef, useState } from 'react';
import { ApiError, get, post, type ReplayResult } from '../api';
import { DecisionChip } from '../components/ClassBadge';
import { clock, target } from '../format';

type Loaded = { source: string; text: string };

// The server refuses anything outside these; checking here says why in
// words instead of showing a bare 400.
const MIN_HOURS = 1;
const MAX_HOURS = 720;
const MAX_POLICY_BYTES = 64 * 1024;

function parseHours(v: string): number | null {
  if (!/^\d+$/.test(v.trim())) return null;
  const n = Number(v.trim());
  return n >= MIN_HOURS && n <= MAX_HOURS ? n : null;
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
  // Prefill the candidate with the loaded policy once, and only if the
  // approver has not started typing: a late response must not wipe an edit.
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
      // 400 is the policy failing to load: the parser's own message, shown
      // exactly, since the line and column in it are what fixes it. Other
      // failures (429 while another replay runs, a server error) are
      // about the request, not the policy.
      if (e instanceof ApiError && e.status === 400) setParseError(e.message);
      else setError(e instanceof Error ? e.message : 'The replay did not run.');
    } finally {
      setBusy(false);
    }
  }

  const n = parseHours(hours);

  return (
    <div className="page page-wide">
      <div className="page-head">
        <div>
          <h1>Policy</h1>
          <p className="lede">The policy blastgate is running, and what a candidate would have decided differently over past requests.</p>
        </div>
      </div>

      <div className="policy-grid">
        <section className="card section">
          <h2>Loaded policy</h2>
          {loadError && (
            <p className="banner-error" role="alert">
              {loadError}
            </p>
          )}
          {loaded === null && !loadError && <p className="loading">Loading…</p>}
          {loaded && (
            <>
              <p className="source">
                From <code className="rule">{loaded.source}</code>
              </p>
              <pre className="code-block code-scroll" aria-label="Loaded policy">
                {loaded.text}
              </pre>
              <p className="dim small">To adopt a different policy, change the policy file and restart blastgate. Nothing here changes the running policy.</p>
            </>
          )}
        </section>

        <section className="card section">
          <h2>Try a candidate</h2>
          <form
            className="replay-form"
            // Our own message says what is wrong; the browser's bubble would
            // block the submit without saying the range.
            noValidate
            onSubmit={(e) => {
              e.preventDefault();
              if (!busy) void replay();
            }}
          >
            <label className="field">
              <span>Candidate policy</span>
              <textarea
                value={candidate}
                onChange={(e) => {
                  touched.current = true;
                  setCandidate(e.target.value);
                }}
                spellCheck={false}
                rows={14}
              />
            </label>
            <div className="replay-row">
              <label className="field field-hours">
                <span>Hours of history</span>
                <input type="number" inputMode="numeric" min={MIN_HOURS} max={MAX_HOURS} step={1} value={hours} onChange={(e) => setHours(e.target.value)} />
              </label>
              <button type="submit" className="btn btn-primary" disabled={busy}>
                {busy ? 'Replaying…' : `Replay over the last ${n ?? 'N'} ${n === 1 ? 'hour' : 'hours'}`}
              </button>
            </div>
            {formError && (
              <p className="form-error" role="alert">
                {formError}
              </p>
            )}
          </form>
        </section>
      </div>

      {parseError && (
        <section className="card section parse-error" role="alert" aria-labelledby="parse-h">
          <h2 id="parse-h">The candidate does not load</h2>
          <pre className="code-block" aria-label="Policy error">
            {parseError}
          </pre>
        </section>
      )}
      {error && (
        <p className="banner-error" role="alert">
          {error}
        </p>
      )}

      {result && <Result r={result} />}
    </div>
  );
}

function Result({ r }: { r: ReplayResult }) {
  const changes = r.changes ?? [];
  return (
    <section className="card section" role="region" aria-label="Replay result">
      <h2>Replay result</h2>
      <dl className="stats stats-3">
        <div className="stat">
          <dt>Evaluated</dt>
          <dd>{r.evaluated}</dd>
        </div>
        <div className={r.changed > 0 ? 'stat alarm' : 'stat zero'}>
          <dt>Changed</dt>
          <dd>{r.changed}</dd>
        </div>
        <div className={r.skipped > 0 ? 'stat' : 'stat zero'}>
          <dt>Skipped</dt>
          <dd>{r.skipped}</dd>
        </div>
      </dl>
      {r.truncated && <p className="note">Only the most recent {r.evaluated} decisions in this window were replayed.</p>}
      {r.skipped > 0 && <p className="dim small">Skipped requests had no stored action or impact to replay against.</p>}
      {changes.length < r.changed && (
        <p className="dim small">
          Showing the first {changes.length} of {r.changed} changes.
        </p>
      )}
      {r.changed === 0 ? (
        <p className="empty-sub">No request would have been decided differently.</p>
      ) : (
        <div className="table-wrap">
          <table className="feed">
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">Request</th>
                <th scope="col">Rule</th>
                <th scope="col">Decision</th>
              </tr>
            </thead>
            <tbody>
              {changes.map((c, i) => (
                <tr key={`${c.request_id}-${i}`}>
                  <td data-label="Time" className="time" title={c.at}>
                    {clock(c.at)}
                  </td>
                  <td data-label="Request">
                    {/* One span: on narrow screens the cell is a flex row. */}
                    <span>
                      <span className="verb">{c.verb}</span> <span className="resource">{c.resource}</span> {target(c.namespace, c.name)}
                    </span>
                  </td>
                  <td data-label="Rule">
                    <span className="change">
                      <code className="rule">{c.rule_before || '—'}</code>
                      <span className="arrow" aria-label="becomes">
                        →
                      </span>
                      <code className="rule">{c.rule_after || '—'}</code>
                    </span>
                  </td>
                  <td data-label="Decision">
                    <span className="change">
                      <DecisionChip decision={c.decision_before} />
                      <span className="arrow" aria-label="becomes">
                        →
                      </span>
                      <DecisionChip decision={c.decision_after} />
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
