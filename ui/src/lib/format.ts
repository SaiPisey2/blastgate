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
export function ago(seconds: number): string {
  const s = Math.max(0, seconds);
  if (s < 45) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86_400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86_400)} d ago`;
}
