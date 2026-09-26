// Pure formatting helpers, framework-free apart from useNow (already a
// hook). format.tsx re-exports these until Task 9 folds the views over.
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
