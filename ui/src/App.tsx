import { useEffect, useRef, useState } from 'react';
import { get, logout, onSignedOut, openStream, subscribe, whoami, type ApprovalSummary, type Me } from './api';
import { navigate, parseHash, useHash, type Route } from './router';
import Shell from './components/Shell';
import EmptyState from './components/EmptyState';
import SignIn from './views/SignIn';
import Feed from './views/Feed';
import Queue from './views/Queue';
import Approval from './views/Approval';
import Agents from './views/Agents';
import PolicyView from './views/PolicyView';
import Bypass from './views/Bypass';

export default function App() {
  const hash = useHash();
  const route = parseHash(hash);
  // undefined: still asking /api/me; null: signed out.
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [pending, setPending] = useState<number | null>(null);
  // Where to go back to after signing in, so a 401 mid-task returns the
  // approver to the screen they were on.
  const returnTo = useRef('#/waiting');
  if (route.name !== 'login' && route.name !== 'notfound' && hash) returnTo.current = hash;

  useEffect(() => {
    const off = onSignedOut(() => setMe(null));
    whoami().then(setMe, () => setMe(null));
    return () => {
      off();
    };
  }, []);

  useEffect(() => {
    if (!me) return;
    if (window.location.hash === '#/login') navigate(returnTo.current);
    // Subscribe first, and let any stream event win over the initial fetch:
    // a fetch answered after an event would put a stale count back.
    let heard = false;
    const off = subscribe('approvals', (ev) => {
      heard = true;
      setPending(ev.count);
    });
    const close = openStream();
    get<ApprovalSummary[]>('/api/approvals?status=pending').then(
      (list) => {
        if (!heard) setPending((list ?? []).length);
      },
      () => {},
    );
    return () => {
      close();
      off();
    };
  }, [me]);

  if (me === undefined) return <div className="boot" aria-busy="true" />;
  if (me === null) return <SignIn onSignedIn={setMe} />;

  return (
    <Shell route={route} pending={pending} me={me} onSignOut={() => void logout().catch(() => {})}>
      <Screen route={route} />
    </Shell>
  );
}

// Screen maps a route to its view. Until the new screens land, each new
// route mounts the old view that does the same job, so nothing an
// approver can reach today goes missing in between.
function Screen({ route }: { route: Route }) {
  switch (route.name) {
    case 'waiting':
    // login: signed in but still on #/login for the moment before the
    // effect above sends the approver back to where they were.
    case 'login':
      return <Queue />;
    case 'activity':
      return <Feed />;
    case 'outside':
      return <Bypass />;
    case 'agents':
      return <Agents />;
    case 'policy':
      return <PolicyView />;
    case 'approval':
      return <Approval id={route.id} />;
    case 'notfound':
      return (
        <div className="page">
          <EmptyState title="There is no such page." sub={<a href="#/waiting">Go to Waiting</a>} />
        </div>
      );
  }
}
