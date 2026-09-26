// Pure formatting helpers, framework-free apart from useNow (already a
// hook).
import { useEffect, useState } from 'react';

// useNow re-renders every `ms` so relative times ("3m ago") stay honest
// on a page an approver leaves open.
export function useNow(ms = 15_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(t);
  }, [ms]);
  return now;
}

export function duration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 10) return 'just now';
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return m % 60 ? `${h}h ${m % 60}m` : `${h}h`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
const dayFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });

export function clock(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const today = new Date().toDateString() === d.toDateString();
  return today ? timeFmt.format(d) : `${dayFmt.format(d)} ${timeFmt.format(d)}`;
}

// hhmm is a fixed 24-hour HH:MM, built by hand: a locale's own format
// can come back as "12:05 AM" or, with hour12 off, "24:05" at midnight.
export function hhmm(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function plural(n: number, word: string, many = word + 's'): string {
  return n === 1 ? word : many;
}

// ago is coarser than duration: it always reads as elapsed time ("2 min
// ago"), for places that never show a live-counting clock, only a stamp.
// Each unit is rounded before checking whether it should be promoted to
// the next one, so a value that rounds up to a full unit (3599s, 86399s)
// promotes instead of printing "60 min ago" or "24 h ago".
export function ago(seconds: number): string {
  if (!Number.isFinite(seconds)) return 'just now';
  const s = Math.max(0, seconds);
  if (s < 45) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.round(h / 24);
  return `${d} d ago`;
}

// A plain argument needs no quotes; anything else is single-quoted, the
// one quoting whose only special character is the quote itself.
const PLAIN = /^[A-Za-z0-9_@%+=:,./-]+$/;

// shellQuote renders an exec command the way a shell would need it typed,
// so "psql -c 'drop table x'" is not shown as four loose words and an
// argument with spaces cannot pass for two.
export function shellQuote(args: string[]): string {
  return args.map((a) => (PLAIN.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`)).join(' ');
}

const str = (v: unknown) => (typeof v === 'string' ? v : '');

// actionText lays out the stored action for reading. The action is the
// engine's normalized JSON; any field may be missing or of the wrong type,
// and none of it is trusted to be anything but text.
export function actionText(action: unknown): string {
  const a = action && typeof action === 'object' ? (action as Record<string, unknown>) : {};
  const lines: string[] = [];
  const verb = str(a.verb);
  const path = str(a.path);
  const raw = str(a.rawQuery);
  if (verb) lines.push(`verb  ${verb}`);
  if (path) lines.push(`path  ${path}${raw ? `?${raw}` : ''}`);
  const q = a.query && typeof a.query === 'object' ? (a.query as Record<string, unknown>) : {};
  const container = Array.isArray(q.container) ? q.container.map(String) : [];
  if (container.length) lines.push(`container  ${container.join(', ')}`);
  const command = Array.isArray(q.command) ? q.command.map(String) : [];
  if (command.length) lines.push(`$ ${shellQuote(command)}`);
  return lines.join('\n');
}
