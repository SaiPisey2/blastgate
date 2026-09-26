import type { ApprovalDetail, ApprovalSummary, BypassRow, FeedRow, Impact, Session } from '../api';

let nextID = 100;

export function feedRow(over: Partial<FeedRow> = {}): FeedRow {
  return {
    id: nextID++,
    at: '2026-09-26T10:15:00Z',
    kind: 'decision',
    request_id: 'r1',
    session: 's1',
    human: 'alice',
    agent: 'coding-agent',
    source: 'kubectl',
    verb: 'delete',
    group: '',
    resource: 'pods',
    subresource: '',
    namespace: 'demo',
    name: 'web-1',
    request_digest: 'd',
    class: 'REVERSIBLE',
    measured: true,
    rule: 'safe-writes',
    decision: 'allow',
    approval_id: '',
    status: 200,
    outcome: 'ok',
    latency_ms: 12,
    snapshot: '',
    ...over,
  };
}

export const ID1 = 'a'.repeat(32);
export const ID2 = 'b'.repeat(32);

export function summary(over: Partial<ApprovalSummary> = {}): ApprovalSummary {
  return {
    id: ID1,
    status: 'pending',
    rule: 'hold-terminal',
    human: 'alice',
    agent: 'coding-agent',
    verb: 'delete',
    resource: 'persistentvolumeclaims',
    namespace: 'demo',
    name: 'data',
    summary: 'TERMINAL, 2 objects, 1 volume with data destroyed',
    class: 'TERMINAL',
    data_destroyed: 1,
    age_seconds: 90,
    created: new Date(Date.now() - 90_000).toISOString(),
    expires: new Date(Date.now() + 600_000).toISOString(),
    ...over,
  };
}

export function impact(over: Partial<Impact> = {}): Impact {
  return {
    class: 'TERMINAL',
    measured: true,
    effects: [
      { kind: 'deleted', object: 'PersistentVolumeClaim/demo/data' },
      { kind: 'destroys-data', object: 'PersistentVolume//pv-1' },
    ],
    dataDestroyed: 1,
    sqlDetected: false,
    dryRunRejected: false,
    undo: 'none',
    ...over,
  };
}

export function detail(s: ApprovalSummary, i: Impact): ApprovalDetail {
  return { ...s, action: { verb: s.verb }, impact: i, decided_by: '', decided: '' };
}

export const SID1 = '1'.repeat(16);
export const SID2 = '2'.repeat(16);

export function session(over: Partial<Session> = {}): Session {
  return {
    id: SID1,
    human: 'alice',
    agent: 'coding-agent',
    created: '2026-09-26T08:00:00Z',
    expires: '2026-09-26T20:00:00Z',
    state: 'active',
    ...over,
  };
}

export function bypassRow(over: Partial<BypassRow> = {}): BypassRow {
  return {
    at: '2026-09-26T09:00:00Z',
    user: 'system:serviceaccount:team-a:deployer',
    groups: ['system:serviceaccounts', 'system:serviceaccounts:team-a'],
    verb: 'delete',
    group: 'apps',
    resource: 'deployments',
    subresource: '',
    namespace: 'team-a',
    name: 'web',
    uid: 'u-1',
    dry_run: false,
    ...over,
  };
}

// deploymentImpact is a delete of a Deployment in sounding's owner-first
// order, plus a claim whose volume is destroyed and one whose fate is not
// known. Object strings are the engine's: group/Kind/namespace/name, with
// the group omitted for core objects and the namespace empty for
// cluster-scoped ones.
export function deploymentImpact(over: Partial<Impact> = {}): Impact {
  return impact({
    effects: [
      { kind: 'destroys', object: 'apps/Deployment/team-a/web' },
      { kind: 'destroys', object: 'apps/ReplicaSet/team-a/web-7d9f8c' },
      { kind: 'destroys', object: 'Pod/team-a/web-7d9f8c-abcde' },
      { kind: 'destroys', object: 'Pod/team-a/web-7d9f8c-fghij' },
      { kind: 'destroys', object: 'PersistentVolumeClaim/team-a/data' },
      {
        kind: 'destroys-data',
        object: 'PersistentVolume//pv-1',
        explanation: 'pvc/data is bound to pv/pv-1 with reclaimPolicy=Delete: the csi driver destroys the underlying volume and the data is not recoverable',
      },
      { kind: 'unknown-data-fate', object: 'PersistentVolumeClaim//scratch', explanation: 'pvc/scratch has no spec.volumeName, so nothing is known about what backs it' },
    ],
    dataDestroyed: 1,
    endpointsLeft: { web: 0, api: 2 },
    pdbViolations: ['team-a/web-pdb'],
    ...over,
  });
}
