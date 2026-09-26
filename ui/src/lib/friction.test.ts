import { describe, expect, it } from 'vitest';
import { canSelfApprove, frictionOf, typedTarget } from './friction';

// Table-driven per the brief: class/measured/data_destroyed -> level/tag/tone.
// unknownImpact is true exactly for the "Impact unknown" rows.
const rows: Array<{
  name: string;
  class: string;
  measured?: boolean;
  data_destroyed: number;
  level: string;
  tag: string;
  tone: string;
}> = [
  { name: 'empty class', class: '', measured: true, data_destroyed: 0, level: 'typed', tag: 'Impact unknown', tone: 'caution' },
  { name: 'unknown class', class: 'SOMETHING_NEW', measured: true, data_destroyed: 0, level: 'typed', tag: 'Impact unknown', tone: 'caution' },
  { name: 'unmeasured terminal', class: 'TERMINAL', measured: false, data_destroyed: 0, level: 'typed', tag: 'Impact unknown', tone: 'caution' },
  { name: 'missing measured field', class: 'READ', measured: undefined, data_destroyed: 0, level: 'typed', tag: 'Impact unknown', tone: 'caution' },
  { name: 'reversible with destroyed data', class: 'REVERSIBLE', measured: true, data_destroyed: 2, level: 'typed', tag: 'Cannot be undone', tone: 'danger' },
  { name: 'terminal', class: 'TERMINAL', measured: true, data_destroyed: 0, level: 'typed', tag: 'Cannot be undone', tone: 'danger' },
  { name: 'authority', class: 'AUTHORITY', measured: true, data_destroyed: 0, level: 'typed', tag: 'Grants access', tone: 'danger' },
  { name: 'compensable', class: 'COMPENSABLE', measured: true, data_destroyed: 0, level: 'confirm-undo', tag: 'Needs a follow-up to undo', tone: 'caution' },
  { name: 'reversible', class: 'REVERSIBLE', measured: true, data_destroyed: 0, level: 'confirm', tag: 'Can be undone', tone: 'ok' },
  { name: 'read', class: 'READ', measured: true, data_destroyed: 0, level: 'confirm', tag: 'Can be undone', tone: 'ok' },
];

describe('frictionOf (summary only)', () => {
  it.each(rows)('$name -> $level / $tag / $tone', (row) => {
    const f = frictionOf({ class: row.class, measured: row.measured as never, data_destroyed: row.data_destroyed });
    expect(f.level).toBe(row.level);
    expect(f.tag).toBe(row.tag);
    expect(f.tone).toBe(row.tone);
    expect(f.unknownImpact).toBe(row.tag === 'Impact unknown');
  });

  it('carries the why string for each tag', () => {
    expect(frictionOf({ class: '', measured: true, data_destroyed: 0 }).why).toBe(
      "blastgate can't tell what this will change, so it needs your decision.",
    );
    expect(frictionOf({ class: 'REVERSIBLE', measured: true, data_destroyed: 2 }).why).toBe('Its data would be destroyed with it.');
    expect(frictionOf({ class: 'TERMINAL', measured: true, data_destroyed: 0 }).why).toBe('This cannot be taken back.');
    expect(frictionOf({ class: 'AUTHORITY', measured: true, data_destroyed: 0 }).why).toBe('This gives an account more access to the cluster.');
    expect(frictionOf({ class: 'COMPENSABLE', measured: true, data_destroyed: 0 }).why).toBe('Undoing this needs a follow-up change.');
    expect(frictionOf({ class: 'REVERSIBLE', measured: true, data_destroyed: 0 }).why).toBe('This can be undone.');
    expect(frictionOf({ class: 'READ', measured: true, data_destroyed: 0 }).why).toBe('This can be undone.');
  });
});

describe('frictionOf (impact overrides)', () => {
  it('an unmeasured impact makes an otherwise-known summary unknown', () => {
    const f = frictionOf({ class: 'REVERSIBLE', measured: true, data_destroyed: 0 }, { measured: false, dataDestroyed: 0 });
    expect(f.level).toBe('typed');
    expect(f.tag).toBe('Impact unknown');
    expect(f.unknownImpact).toBe(true);
  });

  it('impact data destroyed overrides a summary that says none', () => {
    const f = frictionOf({ class: 'REVERSIBLE', measured: true, data_destroyed: 0 }, { measured: true, dataDestroyed: 1 });
    expect(f.level).toBe('typed');
    expect(f.tag).toBe('Cannot be undone');
    expect(f.unknownImpact).toBe(false);
  });

  it('an impact measured as anything other than exactly true fails closed', () => {
    // undefined and non-boolean "truthy" values must not read as measured.
    expect(frictionOf({ class: 'READ', measured: true, data_destroyed: 0 }, { measured: undefined as never, dataDestroyed: 0 }).tag).toBe(
      'Impact unknown',
    );
    expect(frictionOf({ class: 'READ', measured: true, data_destroyed: 0 }, { measured: 1 as never, dataDestroyed: 0 }).tag).toBe(
      'Impact unknown',
    );
  });
});

describe('frictionOf (malformed destroyed counts read as unknown, not zero)', () => {
  it('a non-number, NaN or negative summary count is unknown', () => {
    expect(frictionOf({ class: 'READ', measured: true, data_destroyed: NaN }).tag).toBe('Impact unknown');
    expect(frictionOf({ class: 'READ', measured: true, data_destroyed: -1 }).tag).toBe('Impact unknown');
    expect(frictionOf({ class: 'READ', measured: true, data_destroyed: '2' as never }).tag).toBe('Impact unknown');
    expect(frictionOf({ class: 'READ', measured: true, data_destroyed: Infinity }).tag).toBe('Impact unknown');
  });

  it('the same holds for the impact side, when an impact is given', () => {
    expect(frictionOf({ class: 'READ', measured: true, data_destroyed: 0 }, { measured: true, dataDestroyed: NaN }).tag).toBe(
      'Impact unknown',
    );
    expect(frictionOf({ class: 'READ', measured: true, data_destroyed: 0 }, { measured: true, dataDestroyed: -3 }).tag).toBe(
      'Impact unknown',
    );
  });
});

describe('frictionOf (ladder order: destroyed data outranks a class tag)', () => {
  it('AUTHORITY with destroyed data reads Cannot be undone, not Grants access', () => {
    const f = frictionOf({ class: 'AUTHORITY', measured: true, data_destroyed: 3 });
    expect(f.tag).toBe('Cannot be undone');
    expect(f.tone).toBe('danger');
  });

  it('TERMINAL with destroyed data still reads Cannot be undone', () => {
    const f = frictionOf({ class: 'TERMINAL', measured: true, data_destroyed: 1 });
    expect(f.tag).toBe('Cannot be undone');
  });
});

describe('frictionOf (measured must be the exact boolean true)', () => {
  it('a string "true" does not count as measured', () => {
    expect(frictionOf({ class: 'TERMINAL', measured: 'true' as never, data_destroyed: 0 }).tag).toBe('Impact unknown');
  });

  it('a truthy 1 does not count as measured', () => {
    expect(frictionOf({ class: 'TERMINAL', measured: 1 as never, data_destroyed: 0 }).tag).toBe('Impact unknown');
  });

  it('a lowercase class is not a known class, regardless of measured', () => {
    expect(frictionOf({ class: 'terminal', measured: true, data_destroyed: 0 }).tag).toBe('Impact unknown');
  });
});

describe('typedTarget', () => {
  it('prefers namespace/name', () => {
    expect(typedTarget({ namespace: 'demo', name: 'db-0', resource: 'pods', verb: 'delete' })).toBe('demo/db-0');
  });

  it('falls back to name alone when cluster-scoped', () => {
    expect(typedTarget({ namespace: '', name: 'pv-1', resource: 'persistentvolumes', verb: 'delete' })).toBe('pv-1');
  });

  it('falls back to resource when unnamed', () => {
    expect(typedTarget({ namespace: '', name: '', resource: 'persistentvolumes', verb: 'delete' })).toBe('persistentvolumes');
  });

  it('falls back to verb when resource is empty too', () => {
    expect(typedTarget({ namespace: '', name: '', resource: '', verb: 'deletecollection' })).toBe('deletecollection');
  });

  it('falls back to approve when everything is empty', () => {
    expect(typedTarget({ namespace: '', name: '', resource: '', verb: '' })).toBe('approve');
  });
});

describe('canSelfApprove', () => {
  it('is false for the exact same name', () => {
    expect(canSelfApprove('alice', 'alice')).toBe(false);
  });

  it('is true for different names', () => {
    expect(canSelfApprove('bob', 'alice')).toBe(true);
  });

  it('is exact-case: a case difference still allows approval', () => {
    expect(canSelfApprove('alice', 'Alice')).toBe(true);
  });

  it('trims surrounding whitespace before comparing', () => {
    expect(canSelfApprove(' alice ', 'alice')).toBe(false);
    expect(canSelfApprove('alice', ' alice ')).toBe(false);
  });

  it('an empty meName never blocks, even against an empty human', () => {
    expect(canSelfApprove('', 'alice')).toBe(true);
    expect(canSelfApprove('', '')).toBe(true);
    expect(canSelfApprove('   ', '')).toBe(true);
  });
});

describe('canSelfApprove, carried from review', () => {
  it('a summary with no human at all never blocks', () => {
    expect(canSelfApprove('bob', undefined)).toBe(true);
    expect(canSelfApprove('', undefined)).toBe(true);
  });
});
