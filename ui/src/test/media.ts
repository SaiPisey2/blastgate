// A MediaQueryList stand-in: jsdom has no matchMedia at all, so any code
// that asks for a breakpoint would throw in a test. Every query starts
// out not matching (so Motion's reduced-motion check behaves exactly as
// it did before this mock existed), and setMedia flips one query and
// fires "change" on every list that is watching it, the way a browser
// does when the window crosses a breakpoint.

type Listener = (ev: MediaQueryListEvent) => void;

const matches = new Map<string, boolean>();
const listeners = new Map<string, Set<Listener>>();

function list(query: string): MediaQueryList {
  const set = () => {
    let s = listeners.get(query);
    if (!s) listeners.set(query, (s = new Set()));
    return s;
  };
  const mql = {
    get matches() {
      return matches.get(query) ?? false;
    },
    media: query,
    onchange: null,
    addEventListener: (_type: string, fn: Listener) => set().add(fn),
    removeEventListener: (_type: string, fn: Listener) => set().delete(fn),
    addListener: (fn: Listener) => set().add(fn),
    removeListener: (fn: Listener) => set().delete(fn),
    dispatchEvent: () => true,
  };
  return mql as unknown as MediaQueryList;
}

export function installMatchMedia() {
  Object.defineProperty(window, 'matchMedia', { configurable: true, writable: true, value: list });
}

export function setMedia(query: string, value: boolean) {
  matches.set(query, value);
  const ev = { matches: value, media: query } as MediaQueryListEvent;
  listeners.get(query)?.forEach((fn) => fn(ev));
}

export function resetMedia() {
  matches.clear();
  listeners.clear();
}

export function mediaListenerCount(query: string): number {
  return listeners.get(query)?.size ?? 0;
}
