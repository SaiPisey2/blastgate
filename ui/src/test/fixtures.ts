import type { ApprovalDetail, ApprovalSummary, FeedRow, Impact } from '../api';

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
