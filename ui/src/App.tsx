import { useEffect, useRef, useState } from 'react';
import { get, logout, onSignedOut, openStream, subscribe, whoami, type ApprovalSummary, type Me } from './api';
import { navigate, parseHash, useHash, type Route } from './router';
import Nav from './components/Nav';
import Login from './views/Login';
import Feed from './views/Feed';
import Queue from './views/Queue';

export default function App() {
  const hash = useHash();
  const route = parseHash(hash);
  // undefined: still asking /api/me; null: signed out.
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [pending, setPending] = useState<number | null>(null);
  // Where to go back to after signing in, so a 401 mid-task returns the
  // approver to the screen they were on.
  const returnTo = useRef('#/queue');
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
    const close = openStream();
    get<ApprovalSummary[]>('/api/approvals?status=pending').then(
      (list) => setPending((list ?? []).length),
      () => {},
    );
    const off = subscribe('approvals', (ev) => setPending(ev.count));
    return () => {
      close();
      off();
    };
  }, [me]);

  if (me === undefined) return <div className="boot" aria-busy="true" />;
  if (me === null) return <Login onSignedIn={setMe} />;

  return (
    <div className="shell">
      <Nav route={route} pending={pending} name={me.name} onSignOut={() => void logout().catch(() => {})} />
      <main className="main">
        <Screen route={route} />
      </main>
    </div>
  );
}

function Screen({ route }: { route: Route }) {
  switch (route.name) {
    case 'feed':
    case 'login':
      return <Feed />;
    case 'queue':
      return <Queue />;
    case 'approval':
      return <Later title="Approval" what="The full impact tree for one approval" />;
    case 'sessions':
      return <Later title="Sessions" what="Agent sessions, with revoke" />;
    case 'policy':
      return <Later title="Policy" what="The loaded policy and replay of a candidate over past requests" />;
    case 'bypass':
      return <Later title="Bypass alerts" what="Writes that reached the cluster without going through blastgate" />;
    case 'notfound':
      return (
        <div className="page">
          <div className="empty">
            <p className="empty-title">There is no such page.</p>
            <p className="empty-sub">
              <a href="#/feed">Go to the feed</a>
            </p>
          </div>
        </div>
      );
  }
}

function Later({ title, what }: { title: string; what: string }) {
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>{title}</h1>
          <p className="lede">{what}.</p>
        </div>
      </div>
      <div className="empty">
        <p className="empty-title">Not built yet.</p>
        <p className="empty-sub">This screen arrives in the next release.</p>
      </div>
    </div>
  );
}
