import { useEffect, useSyncExternalStore, type ReactNode } from 'react';
import type { Me } from '../api';
import type { Route } from '../router';
import Button from './Button';
import LiveStatus from './LiveStatus';
import ShortcutHelp from './ShortcutHelp';
import ThemeToggle from './ThemeToggle';

type Tab = { hash: string; label: string; match: Route['name'][] };

// Details belongs to Waiting and outside changes to Activity: they are
// opened from those tabs, so those tabs stay marked while they are open.
const TABS: Tab[] = [
  { hash: '#/waiting', label: 'Waiting', match: ['waiting', 'approval'] },
  { hash: '#/activity', label: 'Activity', match: ['activity', 'outside'] },
  { hash: '#/agents', label: 'Agents', match: ['agents'] },
  { hash: '#/policy', label: 'Policy', match: ['policy'] },
];

// --- announcer ---------------------------------------------------------

// One alert region for the whole console, owned by the shell so every
// screen shares it; two regions speaking at once talk over each other.
let spoken = '';
let timer: ReturnType<typeof setTimeout> | undefined;
const hearers = new Set<() => void>();

function tell() {
  hearers.forEach((fn) => fn());
}

// Long enough for a screen reader to notice the region went empty.
const REFILL_MS = 100;

// announce reads text out through the alert region. The region is emptied
// first and refilled a moment later: a screen reader only speaks a
// change, so "1 new request" twice in a row would otherwise be said once.
export function announce(text: string) {
  clearTimeout(timer);
  spoken = '';
  tell();
  timer = setTimeout(() => {
    spoken = text;
    tell();
  }, REFILL_MS);
}

// resetAnnouncer forgets what was last said and drops a pending refill.
// The store is module state, so without this the next alert region (after
// sign-out and sign-in, or the next test) would mount still holding the
// previous announcement.
export function resetAnnouncer() {
  clearTimeout(timer);
  timer = undefined;
  spoken = '';
  tell();
}

function listen(fn: () => void) {
  hearers.add(fn);
  return () => {
    hearers.delete(fn);
  };
}

function Announcer() {
  const text = useSyncExternalStore(listen, () => spoken);
  // The region goes with the shell; what it last said goes with it.
  useEffect(() => resetAnnouncer, []);
  // Rendered as a text child, never as markup: announcements carry
  // agent and object names.
  return (
    <div id="announcer" role="alert" className="visually-hidden">
      {text}
    </div>
  );
}

// --- shell -------------------------------------------------------------

type Props = { route: Route; pending: number | null; me: Me; onSignOut: () => void; children: ReactNode };

export default function Shell({ route, pending, me, onSignOut, children }: Props) {
  return (
    <div className="shell">
      <header className="shell-header">
        <div className="shell-bar">
          <a className="shell-brand" href="#/waiting">
            blastgate
          </a>
          <nav className="shell-tabs" aria-label="Main">
            {TABS.map((t) => {
              const active = t.match.includes(route.name);
              const count = t.hash === '#/waiting' && pending !== null && pending > 0 ? pending : 0;
              return (
                <a key={t.hash} href={t.hash} className="shell-tab" aria-current={active ? 'page' : undefined}>
                  {t.label}
                  {count > 0 && (
                    <>
                      {/* The badge is for the eye; the words are for the
                          ear, so the link reads "Waiting, 3 requests"
                          instead of "Waiting 3". */}
                      <span className="shell-badge" aria-hidden="true">
                        {count}
                      </span>
                      <span className="visually-hidden">{`, ${count} ${count === 1 ? 'request' : 'requests'}`}</span>
                    </>
                  )}
                </a>
              );
            })}
          </nav>
          <div className="shell-meta">
            <LiveStatus />
            <ThemeToggle />
            <span className="shell-who" title={me.name}>
              {me.name}
            </span>
            <Button className="shell-signout" onClick={onSignOut}>
              Sign out
            </Button>
          </div>
        </div>
      </header>
      <main className="main shell-main">{children}</main>
      <Announcer />
      <ShortcutHelp />
    </div>
  );
}
