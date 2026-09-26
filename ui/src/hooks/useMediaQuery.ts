import { useCallback, useSyncExternalStore } from 'react';

// No matchMedia (a server render, or an old embedded browser) reads as
// "does not match": every caller's false branch is the narrow, one-column
// layout, which works at any width.
function mql(query: string): MediaQueryList | null {
  return typeof window !== 'undefined' && typeof window.matchMedia === 'function' ? window.matchMedia(query) : null;
}

// useMediaQuery reports whether a CSS media query matches, and re-renders
// when the window crosses it. useSyncExternalStore, not state plus an
// effect: the first paint already has the right answer, so a wide screen
// never flashes the narrow layout on load.
export function useMediaQuery(query: string): boolean {
  const subscribe = useCallback(
    (cb: () => void) => {
      const list = mql(query);
      if (!list) return () => {};
      list.addEventListener('change', cb);
      return () => list.removeEventListener('change', cb);
    },
    [query],
  );
  return useSyncExternalStore(
    subscribe,
    () => mql(query)?.matches ?? false,
    () => false,
  );
}
