import { describe, expect, it } from 'vitest';
import { displayClass, fold, keyOf, minRawId, outcomeOf, upsert, type Entry } from './feedModel';
import { feedRow } from '../test/fixtures';

describe('fold/upsert', () => {
  it('decision then result is one entry', () => {
    const decision = feedRow({ id: 60, request_id: 'q1', kind: 'decision', status: 0, outcome: '' });
    const result = feedRow({ id: 63, request_id: 'q1', kind: 'result', status: 403, outcome: 'held' });
    const entries = fold(fold([], [decision]), [result]);
    expect(entries).toHaveLength(1);
    expect(entries[0].done).toBe(true);
    expect(entries[0].row.status).toBe(403);
  });

  it('result then decision is one entry', () => {
    const decision = feedRow({ id: 70, request_id: 'q2', kind: 'decision', status: 0, outcome: '' });
    const result = feedRow({ id: 71, request_id: 'q2', kind: 'result', status: 201, outcome: 'ok' });
    // The result arrives first on the stream, the decision (replayed or
    // reordered) second: the result's status still wins.
    const entries = fold(fold([], [result]), [decision]);
    expect(entries).toHaveLength(1);
    expect(entries[0].done).toBe(true);
    expect(entries[0].row.status).toBe(201);
  });

  it('a merged entry keeps the first row\'s time', () => {
    const decision = feedRow({ id: 80, request_id: 'q3', kind: 'decision', at: '2026-09-26T10:15:00Z', status: 0 });
    const result = feedRow({ id: 81, request_id: 'q3', kind: 'result', at: '2026-09-26T10:45:00Z', status: 101 });
    const entries = fold(fold([], [decision]), [result]);
    expect(entries[0].row.at).toBe('2026-09-26T10:15:00Z');
  });

  it('folding the same row twice changes nothing', () => {
    const r = feedRow({ id: 5, request_id: 'q4' });
    const once = fold([], [r]);
    const twice = fold(once, [r]);
    expect(twice).toEqual(once);
  });

  it('entries order by their first row id', () => {
    const a = feedRow({ id: 10, request_id: 'a' });
    const b = feedRow({ id: 30, request_id: 'b' });
    const c = feedRow({ id: 20, request_id: 'c' });
    const entries = fold([], [a, b, c]);
    expect(entries.map((e) => e.first)).toEqual([30, 20, 10]);
  });

  it('cap trims the oldest', () => {
    const rows = [feedRow({ id: 1, request_id: 'x1' }), feedRow({ id: 2, request_id: 'x2' }), feedRow({ id: 3, request_id: 'x3' })];
    const entries = fold([], rows, 2);
    expect(entries.map((e) => e.first)).toEqual([3, 2]);
  });
});

describe('minRawId', () => {
  it('is the lowest raw id seen, not the lowest entry', () => {
    // A request split across two pages: its decision (the low raw id, 100)
    // is folded in after its result (150), so the entry's own displayed
    // row carries the higher id. minRawId must still report the entry's
    // first (100), not the row's id or the position of the entry in the
    // sorted list.
    const result = feedRow({ id: 150, request_id: 'split', kind: 'result', status: 200, outcome: 'ok' });
    const decision = feedRow({ id: 100, request_id: 'split', kind: 'decision', status: 0, outcome: '' });
    const other = feedRow({ id: 300, request_id: 'other' });
    const entries = fold([], [other, result, decision]);
    const split = entries.find((e) => e.key === keyOf(decision))!;
    expect(split.first).toBe(100);
    expect(split.row.id).toBe(150);
    expect(minRawId(entries)).toBe(100);
  });

  it('is undefined for no entries', () => {
    expect(minRawId([])).toBeUndefined();
  });
});

describe('displayClass', () => {
  it('shows a legacy blank read as READ', () => {
    const legacyRead = feedRow({ kind: 'result', rule: 'read', decision: 'allow', class: '', measured: false });
    expect(displayClass(legacyRead)).toEqual({ cls: 'READ', measured: true });
  });

  it('only shows READ for the exact combination kind=result, rule=read, decision=allow, class=empty', () => {
    const heldBlank = feedRow({ kind: 'result', rule: 'read', decision: 'hold', class: '', measured: false });
    const decisionBlank = feedRow({ kind: 'decision', rule: 'read', decision: 'allow', class: '', measured: false });
    const wrongRule = feedRow({ kind: 'result', rule: 'safe-writes', decision: 'allow', class: '', measured: false });
    for (const r of [heldBlank, decisionBlank, wrongRule]) {
      expect(displayClass(r)).toEqual({ cls: '', measured: false });
    }
  });

  it('leaves a real class alone, even for a read (I2)', () => {
    // Only the blank-class legacy-read combination is special-cased; a row
    // that already carries a real class is shown as-is. Guards against a
    // fix that drops the `class === ''` check and starts overwriting every
    // allowed read's class with the READ label.
    const measuredRead = feedRow({ kind: 'result', rule: 'read', decision: 'allow', class: 'REVERSIBLE', measured: true });
    expect(displayClass(measuredRead)).toEqual({ cls: 'REVERSIBLE', measured: true });
  });
});

describe('outcomeOf', () => {
  function entry(over: Parameters<typeof feedRow>[0], done: boolean): Entry {
    const row = feedRow(over);
    return { key: keyOf(row), first: row.id, row, done };
  }

  it('In flight when not done', () => {
    expect(outcomeOf(entry({ status: 0, outcome: '' }, false))).toBe('In flight');
  });

  it('Waiting for approval when a hold has no result row yet (D-R22)', () => {
    expect(outcomeOf(entry({ kind: 'decision', decision: 'hold', status: 0, outcome: '' }, false))).toBe('Waiting for approval');
  });

  it('Held once a hold has its result row, whatever the status (D-R22)', () => {
    expect(outcomeOf(entry({ kind: 'result', decision: 'hold', status: 200, outcome: '' }, true))).toBe('Held');
    expect(outcomeOf(entry({ kind: 'result', decision: 'hold', status: 403, outcome: 'held' }, true))).toBe('Held');
  });

  it('Denied when the decision is deny', () => {
    expect(outcomeOf(entry({ decision: 'deny', status: 403, outcome: '' }, true))).toBe('Denied');
  });

  it('Failed when the status is 500 or above', () => {
    expect(outcomeOf(entry({ decision: 'allow', status: 502, outcome: '' }, true))).toBe('Failed');
  });

  it('Interrupted for the proxy\'s "aborted" outcome (a forwarded stream dropped)', () => {
    expect(outcomeOf(entry({ decision: 'allow', status: 200, outcome: 'aborted' }, true))).toBe('Interrupted');
  });

  it('Interrupted for the proxy\'s "client cancelled; outcome unknown" outcome', () => {
    expect(outcomeOf(entry({ decision: 'allow', status: 0, outcome: 'client cancelled; outcome unknown' }, true))).toBe('Interrupted');
  });

  it('Interrupted for any other non-empty outcome the server has not been seen to emit yet', () => {
    expect(outcomeOf(entry({ decision: 'allow', status: 200, outcome: 'held' }, true))).toBe('Interrupted');
  });

  it('Allowed when the outcome is empty and nothing else applies', () => {
    expect(outcomeOf(entry({ decision: 'allow', status: 200, outcome: '' }, true))).toBe('Allowed');
  });
});

describe('upsert', () => {
  it('starts a new entry for a row not seen before', () => {
    const m = new Map();
    const r = feedRow({ id: 1, request_id: 'new', kind: 'decision' });
    upsert(m, r);
    expect(m.get(keyOf(r))).toEqual({ key: keyOf(r), first: 1, row: r, done: false });
  });
});
