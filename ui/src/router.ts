import { useSyncExternalStore } from 'react';

// A hash router: the Go server serves one index.html, and hash routes
// never reach it, so no path ever needs a server-side fallback to work.
export type Route =
  | { name: 'feed' }
  | { name: 'queue' }
  | { name: 'approval'; id: string }
  | { name: 'sessions' }
  | { name: 'policy' }
  | { name: 'bypass' }
  | { name: 'login' }
  | { name: 'notfound' };

export const APPROVAL_ID = /^[0-9a-f]{32}$/;

export function parseHash(hash: string): Route {
  const parts = hash.replace(/^#\/?/, '').split('/');
  switch (parts[0]) {
    case '':
    case 'feed':
      return { name: 'feed' };
    case 'queue':
    case 'sessions':
    case 'policy':
    case 'bypass':
    case 'login':
      return parts.length === 1 ? { name: parts[0] } : { name: 'notfound' };
    case 'approvals':
      // Validated here too, so a crafted hash never becomes an API path.
      return parts.length === 2 && APPROVAL_ID.test(parts[1]) ? { name: 'approval', id: parts[1] } : { name: 'notfound' };
  }
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
