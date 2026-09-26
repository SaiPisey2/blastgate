import { describe, expect, it } from 'vitest';
import { ago, clock, duration, plural } from './format';

describe('duration', () => {
  it('rounds seconds under a minute', () => {
    expect(duration(3)).toBe('just now');
    expect(duration(9)).toBe('just now');
    expect(duration(10)).toBe('10s');
    expect(duration(59)).toBe('59s');
  });

  it('shows minutes under an hour', () => {
    expect(duration(60)).toBe('1m');
    expect(duration(3599)).toBe('59m');
  });

  it('shows hours and leftover minutes under a day', () => {
    expect(duration(3600)).toBe('1h');
    expect(duration(3660)).toBe('1h 1m');
    expect(duration(7200)).toBe('2h');
  });

  it('shows days and leftover hours', () => {
    expect(duration(86_400)).toBe('1d 0h');
    expect(duration(90_000)).toBe('1d 1h');
  });

  it('never goes negative', () => {
    expect(duration(-5)).toBe('just now');
  });
});

describe('clock', () => {
  it('falls back to the raw string on an invalid date', () => {
    expect(clock('not-a-date')).toBe('not-a-date');
  });

  it('formats a valid date as a 24h clock reading', () => {
    expect(clock(new Date().toISOString())).toMatch(/^\d{1,2}:\d{2}:\d{2}$/);
  });
});

describe('plural', () => {
  it('keeps the singular for exactly one', () => {
    expect(plural(1, 'pod')).toBe('pod');
  });

  it('uses the default plural for any other count', () => {
    expect(plural(0, 'pod')).toBe('pods');
    expect(plural(2, 'pod')).toBe('pods');
  });

  it('accepts an irregular plural', () => {
    expect(plural(2, 'stateful set', 'stateful sets')).toBe('stateful sets');
    expect(plural(1, 'stateful set', 'stateful sets')).toBe('stateful set');
  });
});

describe('ago', () => {
  it('says just now under 45 seconds', () => {
    expect(ago(0)).toBe('just now');
    expect(ago(44)).toBe('just now');
  });

  it('switches to minutes at 45 seconds', () => {
    expect(ago(45)).toBe('1 min ago');
    expect(ago(119)).toBe('2 min ago');
  });

  it('switches to hours at 3600 seconds', () => {
    expect(ago(3600)).toBe('1 h ago');
  });

  it('switches to days once past a day', () => {
    expect(ago(90_000)).toBe('1 d ago');
  });

  it('promotes a value that rounds up to a full unit instead of overflowing it', () => {
    // 3599/60 = 59.98 min, which rounds to 60: that must promote to
    // hours rather than print "60 min ago".
    expect(ago(3599)).toBe('1 h ago');
    // 86399/3600 = 24.0 h once minutes have already rounded up, which
    // must promote to days rather than print "24 h ago".
    expect(ago(86_399)).toBe('1 d ago');
  });

  it('reads as just now for a non-finite input', () => {
    expect(ago(NaN)).toBe('just now');
    expect(ago(Infinity)).toBe('just now');
  });
});
