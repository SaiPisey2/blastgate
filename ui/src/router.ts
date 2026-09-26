import { useSyncExternalStore } from 'react';

// A hash router: the Go server serves one index.html, and hash routes
// never reach it, so no path ever needs a server-side fallback to work.
export type Route =
  | { name: 'waiting' }
  | { name: 'activity' }
  | { name: 'outside' }
  | { name: 'agents' }
  | { name: 'policy' }
  | { name: 'approval'; id: string }
  | { name: 'login' }
  | { name: 'notfound' };

export const APPROVAL_ID = /^[0-9a-f]{32}$/;

// Single-segment hashes. The old names stay as aliases: bookmarks, chat
// links and webhook messages were written against #/queue, #/feed,
// #/bypass and #/sessions, and a link that lands on "no such page" is a
// request nobody gets to in time. A Map, not an object literal, so a hash
// like #/constructor never finds a prototype key.
const PAGES = new Map<string, Route>([
  ['', { name: 'waiting' }],
  ['waiting', { name: 'waiting' }],
  ['activity', { name: 'activity' }],
  ['agents', { name: 'agents' }],
  ['policy', { name: 'policy' }],
  ['login', { name: 'login' }],
  ['queue', { name: 'waiting' }],
  ['feed', { name: 'activity' }],
  ['bypass', { name: 'outside' }],
  ['sessions', { name: 'agents' }],
]);

export function parseHash(hash: string): Route {
  const parts = hash.replace(/^#\/?/, '').split('/');
  if (parts.length === 1) return PAGES.get(parts[0]) ?? { name: 'notfound' };
  if (parts.length === 2 && parts[0] === 'activity' && parts[1] === 'outside') return { name: 'outside' };
  // Validated here too, so a crafted hash never becomes an API path.
  if (parts.length === 2 && parts[0] === 'approvals' && APPROVAL_ID.test(parts[1])) return { name: 'approval', id: parts[1] };
  return { name: 'notfound' };
}

function subscribe(cb: () => void) {
  window.addEventListener('hashchange', cb);
  return () => window.removeEventListener('hashchange', cb);
}

export function useHash(): string {
  return useSyncExternalStore(subscribe, () => window.location.hash);
}

export function navigate(hash: string) {
  window.location.hash = hash;
}
