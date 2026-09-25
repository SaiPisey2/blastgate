import type { Route } from '../router';

type Item = { hash: string; label: string; match: Route['name'][] };

const ITEMS: Item[] = [
  { hash: '#/feed', label: 'Feed', match: ['feed'] },
  { hash: '#/queue', label: 'Queue', match: ['queue', 'approval'] },
  { hash: '#/sessions', label: 'Sessions', match: ['sessions'] },
  { hash: '#/policy', label: 'Policy', match: ['policy'] },
  { hash: '#/bypass', label: 'Bypass', match: ['bypass'] },
];

type Props = { route: Route; pending: number | null; name: string; onSignOut: () => void };

export default function Nav({ route, pending, name, onSignOut }: Props) {
  return (
    <header className="topbar">
      <div className="topbar-inner">
        <a className="brand" href="#/feed" aria-label="blastgate home">
          <span className="brand-mark" aria-hidden="true" />
          blastgate
        </a>
        <nav className="nav" aria-label="Main">
          {ITEMS.map((it) => {
            const active = it.match.includes(route.name);
            return (
              <a key={it.hash} href={it.hash} className={active ? 'nav-link active' : 'nav-link'} aria-current={active ? 'page' : undefined}>
                {it.label}
                {it.hash === '#/queue' && pending !== null && pending > 0 && (
                  <span className="count" aria-label={`${pending} pending`}>
                    {pending}
                  </span>
                )}
              </a>
            );
          })}
        </nav>
        <div className="who">
          <span className="who-name" title="Signed in approver">
            {name}
          </span>
          <button type="button" className="btn btn-ghost btn-small" onClick={onSignOut}>
            Sign out
          </button>
        </div>
      </div>
    </header>
  );
}
