import { useEffect, useRef, useState } from 'react';
import { clusterOf, get, logout, onSignedOut, openStream, subscribe, whoami, type Me } from './api';
import { navigate, parseHash, useHash, type Route } from './router';
import Shell from './components/Shell';
import EmptyState from './components/EmptyState';
import SignIn from './views/SignIn';
import Activity from './views/Activity';
import Waiting from './views/Waiting';
import Details from './views/Details';
import Agents from './views/Agents';
import Policy from './views/Policy';
import Outside from './views/Outside';

export default function App() {
  const hash = useHash();
  const route = parseHash(hash);
  // undefined: still asking /api/me; null: signed out.
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [pending, setPending] = useState<number | null>(null);
  // The cluster when the answer that signed us in did not carry it (a
  // server older than this console). Its own state, not merged into me: a new me would restart the
  // stream and refetch the count.
  const [fetchedCluster, setFetchedCluster] = useState('');
  // Where to go back to after signing in, so a 401 mid-task returns the
  // approver to the screen they were on.
  const returnTo = useRef('#/waiting');
  if (route.name !== 'login' && route.name !== 'notfound' && hash) returnTo.current = hash;
  // The last screen before a details page, so Esc there goes back to it:
  // Activity when the approver came from Activity, Waiting otherwise and
  // on a direct load. Read during render, like returnTo: on the details
  // page's first render it still holds the screen before it.
  const before = useRef<Route['name']>('waiting');
  if (route.name !== 'approval' && route.name !== 'login' && route.name !== 'notfound') before.current = route.name;
  const back = before.current === 'activity' ? '#/activity' : '#/waiting';

  useEffect(() => {
    const off = onSignedOut(() => setMe(null));
    whoami().then(setMe, () => setMe(null));
    return () => {
      off();
    };
  }, []);

  useEffect(() => {
    if (!me || typeof me.cluster === 'string') return;
    let live = true;
    clusterOf().then(
      (c) => {
        if (live) setFetchedCluster(c);
      },
      () => {},
    );
    return () => {
      live = false;
    };
  }, [me]);

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
    // The true count, not the length of a list the server caps at 500.
    get<{ count?: unknown }>('/api/approvals/count').then(
      (r) => {
        if (!heard && r && typeof r.count === 'number' && Number.isFinite(r.count)) setPending(r.count);
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
  // Type-checked: a cluster that is not a string is no cluster at all.
  const cluster = typeof me.cluster === 'string' ? me.cluster : fetchedCluster;

  return (
    <Shell route={route} pending={pending} me={{ ...me, cluster }} onSignOut={() => void logout().catch(() => {})}>
      <Screen route={route} me={me.name} cluster={cluster} back={back} />
    </Shell>
  );
}

// Screen maps a route to its view. Until the new screens land, each new
// route mounts the old view that does the same job, so nothing an
// approver can reach today goes missing in between.
function Screen({ route, me, cluster, back }: { route: Route; me: string; cluster: string; back: string }) {
  switch (route.name) {
    case 'waiting':
    // login: signed in but still on #/login for the moment before the
    // effect above sends the approver back to where they were.
    case 'login':
      return <Waiting me={me} cluster={cluster} />;
    case 'activity':
      return <Activity />;
    case 'outside':
      return <Outside />;
    case 'agents':
      return <Agents />;
    case 'policy':
      return <Policy />;
    case 'approval':
      return <Details id={route.id} me={me} cluster={cluster} back={back} />;
    case 'notfound':
      return (
        <div className="page">
          <EmptyState title="There is no such page." sub={<a href="#/waiting">Go to Waiting</a>} />
        </div>
      );
  }
}
