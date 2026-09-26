// Demo fixtures for looking at the console on the dev server without a
// cluster: `npm run dev`, then open /?demo (or ?demo=empty for the empty
// states, ?demo=signedout for sign in). main.tsx loads this module only
// when import.meta.env.DEV is true, which a build replaces with false, so
// neither the branch nor this file reaches dist/. The Go embed guard fails
// the build's test if DEMO_MARKER is ever found there.
import { setStreamStatus, type ApprovalDetail, type ApprovalSummary, type BypassRow, type FeedRow, type Impact, type ReplayResult, type Session } from '../api';

export const DEMO_MARKER = 'blastgate-demo-fixture';

const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const ahead = (s: number) => new Date(Date.now() + s * 1000).toISOString();
const id = (c: string) => c.repeat(32);

function held(over: Partial<ApprovalSummary>): ApprovalSummary {
  return {
    id: id('a'),
    status: 'pending',
    rule: 'hold-terminal',
    human: 'priya.raman',
    agent: 'coding-agent',
    verb: 'delete',
    resource: 'persistentvolumeclaims',
    namespace: 'payments',
    name: 'ledger-data',
    summary: 'TERMINAL, 3 objects, 1 volume with data destroyed',
    class: 'TERMINAL',
    data_destroyed: 1,
    measured: true,
    age_seconds: 420,
    created: ago(420),
    expires: ahead(480),
    ...over,
  };
}

const pending: ApprovalSummary[] = [
  held({}),
  held({
    id: id('b'),
    rule: 'hold-writes',
    verb: 'patch',
    resource: 'deployments/scale',
    namespace: 'checkout',
    name: 'cart-api',
    summary: 'REVERSIBLE, 7 objects',
    class: 'REVERSIBLE',
    data_destroyed: 0,
    human: 'tomasz.wojcik',
    agent: 'release-bot',
    age_seconds: 130,
    created: ago(130),
  }),
  held({
    id: id('c'),
    rule: 'hold-exec',
    verb: 'create',
    resource: 'pods/exec',
    namespace: 'payments',
    name: 'ledger-db-0',
    summary: 'TERMINAL, 0 objects, not measured',
    class: 'TERMINAL',
    data_destroyed: 0,
    measured: false,
    age_seconds: 55,
    created: ago(55),
  }),
  held({
    id: id('d'),
    rule: 'hold-authority',
    verb: 'create',
    resource: 'clusterrolebindings',
    namespace: '',
    name: 'ci-deployer-admin',
    summary: 'AUTHORITY, 1 object',
    class: 'AUTHORITY',
    data_destroyed: 0,
    human: 'demo',
    age_seconds: 12,
    created: ago(12),
  }),
];

const impacts: Record<string, Impact> = {
  [id('a')]: {
    class: 'TERMINAL',
    measured: true,
    effects: [
      { kind: 'destroys', object: 'PersistentVolumeClaim/payments/ledger-data' },
      {
        kind: 'destroys-data',
        object: 'PersistentVolume//pvc-5d1e9a07',
        explanation: 'pvc/ledger-data is bound to pv/pvc-5d1e9a07 with reclaimPolicy=Delete: the csi driver destroys the volume and the data is not recoverable',
      },
      { kind: 'orphans', object: 'apps/StatefulSet/payments/ledger-db', explanation: 'ledger-db mounts ledger-data; its pod will not start again without it' },
    ],
    dataDestroyed: 1,
    endpointsLeft: { 'ledger-db': 0 },
    pdbViolations: ['payments/ledger-db-pdb'],
    sqlDetected: false,
    dryRunRejected: false,
    undo: 'none',
  },
  [id('b')]: {
    class: 'REVERSIBLE',
    measured: true,
    effects: [
      { kind: 'scales-down', object: 'apps/Deployment/checkout/cart-api', explanation: 'replicas 6 -> 0' },
      { kind: 'destroys', object: 'apps/ReplicaSet/checkout/cart-api-7c9d4f8b6' },
      ...['k2x9q', 'm4p7z', 'r8t2w', 'v3n6b', 'x7c1d', 'z5h8j'].map((s) => ({ kind: 'destroys', object: `Pod/checkout/cart-api-7c9d4f8b6-${s}` })),
    ],
    dataDestroyed: 0,
    endpointsLeft: { 'cart-api': 0 },
    sqlDetected: false,
    dryRunRejected: false,
    undo: 'objects',
  },
  [id('c')]: {
    class: 'TERMINAL',
    measured: false,
    reason: 'exec is not measured',
    effects: [],
    dataDestroyed: 0,
    sqlDetected: true,
    dryRunRejected: false,
    undo: '',
  },
  [id('d')]: {
    class: 'AUTHORITY',
    measured: true,
    effects: [{ kind: 'grants', object: 'rbac.authorization.k8s.io/ClusterRoleBinding//ci-deployer-admin', explanation: 'binds cluster-admin to serviceaccount ci/deployer' }],
    dataDestroyed: 0,
    sqlDetected: false,
    dryRunRejected: false,
    undo: 'objects',
  },
};

const actions: Record<string, unknown> = {
  [id('a')]: { verb: 'delete', path: '/api/v1/namespaces/payments/persistentvolumeclaims/ledger-data' },
  [id('b')]: { verb: 'patch', path: '/apis/apps/v1/namespaces/checkout/deployments/cart-api/scale' },
  [id('c')]: {
    verb: 'create',
    path: '/api/v1/namespaces/payments/pods/ledger-db-0/exec',
    query: { command: ['psql', '-c', 'delete from ledger_entries where settled_at < now() - interval 90 days'], container: ['postgres'] },
  },
  [id('d')]: { verb: 'create', path: '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings' },
};

// An expired request, reachable from the held Activity row.
const expired: ApprovalDetail = {
  ...held({ id: id('e'), status: 'expired', verb: 'delete', resource: 'namespaces', namespace: '', name: 'staging-eu', created: ago(5400), expires: ago(3600) }),
  action: { verb: 'delete', path: '/api/v1/namespaces/staging-eu' },
  impact: { class: 'TERMINAL', measured: true, effects: [{ kind: 'destroys', object: 'Namespace//staging-eu' }], dataDestroyed: 0, sqlDetected: false, dryRunRejected: false, undo: 'none' },
  decided_by: '',
  decided: ago(3600),
};

let row = 9000;
function feed(over: Partial<FeedRow>): FeedRow {
  const n = row--;
  return {
    id: n,
    at: ago((9000 - n) * 97 + 30),
    kind: 'result',
    request_id: `q${n}`,
    session: 's1',
    human: 'priya.raman',
    agent: 'coding-agent',
    source: 'kubectl',
    verb: 'get',
    group: '',
    resource: 'pods',
    subresource: '',
    namespace: 'payments',
    name: '',
    request_digest: 'd',
    class: 'READ',
    measured: true,
    rule: 'read',
    decision: 'allow',
    approval_id: '',
    status: 200,
    outcome: '',
    latency_ms: 14,
    snapshot: '',
    ...over,
  };
}

function feedRows(): FeedRow[] {
  row = 9000;
  return [
    feed({ kind: 'decision', decision: 'hold', class: 'AUTHORITY', verb: 'create', resource: 'clusterrolebindings', namespace: '', name: 'ci-deployer-admin', approval_id: id('d'), rule: 'hold-authority', status: 0 }),
    feed({ kind: 'decision', decision: 'hold', class: 'TERMINAL', measured: false, verb: 'create', resource: 'pods', subresource: 'exec', name: 'ledger-db-0', approval_id: id('c'), rule: 'hold-exec', status: 0 }),
    feed({ verb: 'list', resource: 'deployments', namespace: 'checkout', human: 'tomasz.wojcik', agent: 'release-bot' }),
    feed({ kind: 'decision', decision: 'hold', class: 'REVERSIBLE', verb: 'patch', resource: 'deployments', subresource: 'scale', namespace: 'checkout', name: 'cart-api', approval_id: id('b'), rule: 'hold-writes', status: 0, human: 'tomasz.wojcik', agent: 'release-bot' }),
    feed({ decision: 'deny', class: 'TERMINAL', verb: 'delete', resource: 'namespaces', namespace: '', name: 'payments', rule: 'deny-namespace-delete', status: 403 }),
    feed({ class: 'REVERSIBLE', verb: 'patch', resource: 'configmaps', namespace: 'checkout', name: 'cart-api-flags', rule: 'safe-writes' }),
    feed({ kind: 'decision', decision: 'hold', class: 'TERMINAL', verb: 'delete', resource: 'persistentvolumeclaims', name: 'ledger-data', approval_id: id('a'), rule: 'hold-terminal', status: 0 }),
    feed({ verb: 'get', resource: 'pods', subresource: 'log', name: 'ledger-db-0' }),
    feed({ decision: 'hold', class: 'TERMINAL', verb: 'delete', resource: 'namespaces', namespace: '', name: 'staging-eu', approval_id: id('e'), rule: 'hold-terminal', status: 0 }),
    feed({ class: 'COMPENSABLE', verb: 'create', resource: 'jobs', namespace: 'payments', name: 'ledger-reindex', rule: 'safe-writes', status: 201 }),
    feed({ class: 'REVERSIBLE', verb: 'patch', resource: 'deployments', namespace: 'checkout', name: 'cart-api', rule: 'safe-writes', status: 500 }),
    feed({ verb: 'watch', resource: 'events', namespace: 'checkout', outcome: 'aborted' }),
  ];
}

const bypass: BypassRow[] = [
  {
    at: ago(1800),
    user: 'system:serviceaccount:ci:deployer',
    groups: ['system:serviceaccounts', 'system:serviceaccounts:ci'],
    verb: 'patch',
    group: 'apps',
    resource: 'deployments',
    subresource: '',
    namespace: 'checkout',
    name: 'cart-api',
    uid: 'u-1',
    dry_run: false,
  },
  {
    at: ago(7300),
    user: 'marta.oyelaran@corp.example',
    groups: ['sre-oncall'],
    verb: 'delete',
    group: '',
    resource: 'pods',
    subresource: '',
    namespace: 'payments',
    name: 'ledger-db-0',
    uid: 'u-2',
    dry_run: true,
  },
];

const sessions: Session[] = [
  { id: '1'.repeat(16), human: 'priya.raman', agent: 'coding-agent', created: ago(3600), expires: ahead(39600), state: 'active' },
  { id: '2'.repeat(16), human: 'tomasz.wojcik', agent: 'release-bot', created: ago(7200), expires: ahead(1500), state: 'active' },
  { id: '3'.repeat(16), human: 'priya.raman', agent: 'triage-agent', created: ago(90000), expires: ago(3600), state: 'expired' },
  { id: '4'.repeat(16), human: 'marta.oyelaran', agent: 'coding-agent', created: ago(20000), expires: ahead(20000), state: 'revoked' },
];

const policy = `# Loaded from /etc/blastgate/policy.yaml
rules:
  - name: read
    match: { verbs: [get, list, watch] }
    decision: allow
  - name: deny-namespace-delete
    match: { verbs: [delete], resources: [namespaces] }
    unless: "request.name.startsWith('staging-')"
    decision: deny
  - name: hold-terminal
    match: { class: TERMINAL }
    decision: hold
  - name: safe-writes
    match: { class: [REVERSIBLE, COMPENSABLE] }
    decision: allow
`;

const replay: ReplayResult = {
  evaluated: 412,
  changed: 3,
  skipped: 0,
  truncated: false,
  changes: [
    { at: ago(3000), request_id: 'q1', verb: 'patch', resource: 'deployments', namespace: 'checkout', name: 'cart-api', rule_before: 'hold-writes', rule_after: 'safe-writes', decision_before: 'hold', decision_after: 'allow' },
    { at: ago(9000), request_id: 'q2', verb: 'delete', resource: 'pods', namespace: 'payments', name: 'ledger-db-0', rule_before: 'safe-writes', rule_after: 'hold-terminal', decision_before: 'allow', decision_after: 'hold' },
    { at: ago(15000), request_id: 'q3', verb: 'delete', resource: 'namespaces', namespace: '', name: 'staging-eu', rule_before: 'hold-terminal', rule_after: 'deny-namespace-delete', decision_before: 'hold', decision_after: 'deny' },
  ],
};

function json(body: unknown, status = 200): Response {
  return new Response(body === undefined ? '' : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

// install answers /api/* in the page itself. mode: '' for a busy console,
// 'empty' for every empty state, 'signedout' for the sign-in page.
export function install(mode: string) {
  document.documentElement.dataset.demo = DEMO_MARKER;
  const empty = mode === 'empty';
  let signedIn = mode !== 'signedout';
  const waiting = empty ? [] : [...pending];
  const real = window.fetch.bind(window);

  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, window.location.origin);
    if (!url.pathname.startsWith('/api/')) return real(input, init);
    const method = (init?.method ?? 'GET').toUpperCase();
    const path = url.pathname;
    if (path === '/api/login' && method === 'POST') {
      signedIn = true;
      return json({ name: 'demo', csrf: 'demo' });
    }
    if (!signedIn) return json({ error: 'unauthorized' }, 401);
    if (path === '/api/me') return json({ name: 'demo', csrf: 'demo' });
    if (path === '/api/logout') {
      signedIn = false;
      return json({});
    }
    if (path === '/api/approvals') return json(waiting);
    const m = /^\/api\/approvals\/([0-9a-f]{32})(?:\/(approve|deny))?$/.exec(path);
    if (m) {
      if (m[2]) {
        const i = waiting.findIndex((s) => s.id === m[1]);
        if (i < 0) return json({ error: 'not pending' }, 409);
        waiting.splice(i, 1);
        return json({});
      }
      if (m[1] === expired.id) return json(expired);
      const s = pending.find((x) => x.id === m[1]);
      if (!s) return json({ error: 'not found' }, 404);
      return json({ ...s, status: waiting.includes(s) ? 'pending' : 'approved', action: actions[s.id], impact: impacts[s.id], decided_by: '', decided: '' });
    }
    if (path === '/api/feed') return json(empty || url.searchParams.get('before') ? [] : feedRows());
    if (path === '/api/bypass') return json(empty ? [] : bypass);
    if (path === '/api/sessions') return json(empty ? [] : sessions);
    if (/^\/api\/sessions\/[^/]+\/revoke$/.test(path)) return json({});
    if (path === '/api/policy') return json({ source: '/etc/blastgate/policy.yaml', text: policy });
    if (path === '/api/policy/replay') return json(empty ? { ...replay, changed: 0, changes: [] } : replay);
    return json({ error: 'not found' }, 404);
  };

  // No stream in the demo: openStream does nothing without EventSource,
  // and the header shows Live as it would on a connected console.
  Object.defineProperty(window, 'EventSource', { configurable: true, value: undefined });
  setStreamStatus('live');
}
