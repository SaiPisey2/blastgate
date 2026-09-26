import type { FeedRow } from '../api';

// Live rows accumulate on a page left open all day; past this the oldest
// fall off the bottom ("load older" still reaches them).
export const MAX_ROWS = 1000;

// A write leaves two audit rows: a decision row when the gate decides
// and a result row when the request ends, carrying the same rule,
// decision and class plus the status. A read leaves only the result. The
// feed shows one line per request, so the rows are folded by request_id.
// Dropping the decision rows instead would hide an exec, attach or
// port-forward until it closed.
export type Entry = {
  key: string;
  // first is the lowest audit id seen for the request: its place in the
  // feed (the moment it was decided), and what "load older" pages before.
  first: number;
  // row is what is shown. The result row's fields win over the decision's
  // whichever arrives first, so a replayed decision cannot undo a status.
  row: FeedRow;
  // done: the result row has been seen. Until then the request is in flight.
  done: boolean;
};

// A row without a request id stands alone rather than merging with every
// other row that lacks one.
export function keyOf(r: FeedRow): string {
  return r.request_id ? `r:${r.request_id}` : `id:${r.id}`;
}

export function upsert(m: Map<string, Entry>, r: FeedRow): void {
  const key = keyOf(r);
  const result = r.kind === 'result';
  const e = m.get(key);
  if (!e) {
    m.set(key, { key, first: r.id, row: r, done: result });
    return;
  }
  const merged = result || !e.done ? { ...e.row, ...r } : { ...r, ...e.row };
  // The row keeps the time of its request's first row, the one it is
  // ordered by, so a long exec does not show its end time out of order.
  const row = { ...merged, at: r.id < e.first ? r.at : e.row.at };
  m.set(key, { key, first: Math.min(e.first, r.id), row, done: e.done || result });
}

// fold merges raw audit rows into the entries, newest request first. The
// same row folded twice changes nothing, so a stream that resumes and
// repeats rows cannot duplicate a line (P2-R24). cap trims the oldest; a
// page loaded on request is not trimmed away as soon as it arrives.
export function fold(entries: Entry[], rows: FeedRow[], cap = MAX_ROWS): Entry[] {
  const m = new Map(entries.map((e) => [e.key, e]));
  for (const r of rows) upsert(m, r);
  return [...m.values()].sort((a, b) => b.first - a.first).slice(0, cap);
}

// displayClass is the class a row is shown with, and whether it was
// measured. Builds before the fix for reads recorded an allowed read's
// result row with an empty class, which the fail-closed badge would paint
// red as UNMEASURED. Only that exact combination is read as a measured
// READ; every other empty class stays unmeasured (P2-R14).
export function displayClass(r: FeedRow): { cls: string; measured: boolean } {
  if (r.class === '' && r.kind === 'result' && r.rule === 'read' && r.decision === 'allow') return { cls: 'READ', measured: true };
  return { cls: r.class, measured: r.measured };
}

// minRawId is the lowest raw audit id folded into any entry: every row of
// every entry is at or above its entry's first, so this is the cursor
// "load older" pages before. A request whose decision is on the next page
// merges into the line its result already made.
export function minRawId(entries: Entry[]): number | undefined {
  if (entries.length === 0) return undefined;
  return Math.min(...entries.map((e) => e.first));
}

// outcomeOf is the plain-language state a row shows in place of a raw
// status code: what a person reading the feed wants to know before they
// read the rule or the number. Decision strings (allow/hold/deny) come
// from the gate's policy.Decision; outcome/status come from the result
// row the gate appends in Complete.
// The proxy never sets outcome to "error"; its two real abnormal outcomes
// are "aborted" (a forwarded stream dropped) and "client cancelled;
// outcome unknown" (outcomeAborted/outcomeUnknown, internal/proxy/proxy.go).
// Either one, or any other non-empty outcome a future build adds, reads as
// Interrupted rather than Allowed.
export type Outcome = 'Allowed' | 'Waiting for approval' | 'Held' | 'Denied' | 'In flight' | 'Failed' | 'Interrupted';

// A hold keeps decision "hold" on both of its rows (gate.row: the
// policy's decision, not what happened). Without a result row the
// request is still waiting for an approver; with one, the gate has
// answered the agent (approved, refused or expired) and the approval's
// own page says which (ruling D-R22).
export function outcomeOf(e: Entry): Outcome {
  if (e.row.decision === 'hold') return e.done ? 'Held' : 'Waiting for approval';
  if (!e.done) return 'In flight';
  if (e.row.decision === 'deny') return 'Denied';
  if (e.row.status >= 500) return 'Failed';
  if (e.row.outcome !== '') return 'Interrupted';
  return 'Allowed';
}
