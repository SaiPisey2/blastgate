import { describe, expect, it } from 'vitest';
import { buildTree, parseObject, UNRECOGNISED } from './tree';
import type { Effect } from '../api';

// The tree's model, without the component: moved here with buildTree and
// parseObject from the old ImpactTree, whose rendering tests now live in
// components/ImpactTree.test.tsx.
describe('tree model', () => {
  // placement maps each object to the object it was drawn under ('' for
  // the top of its namespace).
  function placement(effects: Effect[]) {
    const where: Record<string, string> = {};
    const walk = (nodes: ReturnType<typeof buildTree>[number]['roots'], parent: string) => {
      for (const n of nodes) {
        where[n.ref.raw] = parent;
        walk(n.children, n.ref.raw);
      }
    };
    for (const g of buildTree(effects)) walk(g.roots, '');
    return where;
  }
  const d = (object: string) => ({ kind: 'destroys', object });

  it('an owner is inferred only when the rest of the name has the controller shape', () => {
    // Each child's real owner is absent from the impact; a bare prefix
    // match would draw it under a shorter, unrelated owner.
    expect(
      placement([d('apps/Deployment/team-a/web'), d('apps/ReplicaSet/team-a/web-api-7d9f8c6b5'), d('Pod/team-a/web-api-7d9f8c6b5-abcde')]),
    ).toEqual({
      'apps/Deployment/team-a/web': '',
      'apps/ReplicaSet/team-a/web-api-7d9f8c6b5': '',
      'Pod/team-a/web-api-7d9f8c6b5-abcde': 'apps/ReplicaSet/team-a/web-api-7d9f8c6b5',
    });
    expect(placement([d('apps/StatefulSet/team-a/web'), d('Pod/team-a/web-api-7d9f8c6b5-abcde'), d('Pod/team-a/web-foo')])).toEqual({
      'apps/StatefulSet/team-a/web': '',
      'Pod/team-a/web-api-7d9f8c6b5-abcde': '',
      'Pod/team-a/web-foo': '',
    });
    expect(placement([d('apps/ReplicaSet/team-a/web-7d9f8c6b5'), d('Pod/team-a/web-7d9f8c6b5-extra-abcde')])).toEqual({
      'apps/ReplicaSet/team-a/web-7d9f8c6b5': '',
      'Pod/team-a/web-7d9f8c6b5-extra-abcde': '',
    });
    expect(placement([d('batch/CronJob/team-a/backup'), d('batch/Job/team-a/backup-db-28123456')])).toEqual({
      'batch/CronJob/team-a/backup': '',
      'batch/Job/team-a/backup-db-28123456': '',
    });
  });

  it('the controller shapes still nest', () => {
    expect(
      placement([
        d('apps/Deployment/team-a/web'),
        d('apps/ReplicaSet/team-a/web-7d9f8c6b5'),
        d('Pod/team-a/web-7d9f8c6b5-abcde'),
        d('apps/Deployment/team-a/web-api'),
        d('apps/ReplicaSet/team-a/web-api-5f6d7c8b9'),
        d('apps/StatefulSet/team-a/db'),
        d('Pod/team-a/db-0'),
        d('Pod/team-a/db-12'),
        d('apps/DaemonSet/team-a/agent'),
        d('Pod/team-a/agent-q8w2z'),
        d('batch/CronJob/team-a/backup'),
        d('batch/Job/team-a/backup-28123456'),
        d('Pod/team-a/backup-28123456-x7k2p'),
      ]),
    ).toEqual({
      'apps/Deployment/team-a/web': '',
      'apps/ReplicaSet/team-a/web-7d9f8c6b5': 'apps/Deployment/team-a/web',
      'Pod/team-a/web-7d9f8c6b5-abcde': 'apps/ReplicaSet/team-a/web-7d9f8c6b5',
      'apps/Deployment/team-a/web-api': '',
      // web-api's ReplicaSet, not web's: the rest after "web-" has a dash.
      'apps/ReplicaSet/team-a/web-api-5f6d7c8b9': 'apps/Deployment/team-a/web-api',
      'apps/StatefulSet/team-a/db': '',
      'Pod/team-a/db-0': 'apps/StatefulSet/team-a/db',
      'Pod/team-a/db-12': 'apps/StatefulSet/team-a/db',
      'apps/DaemonSet/team-a/agent': '',
      'Pod/team-a/agent-q8w2z': 'apps/DaemonSet/team-a/agent',
      'batch/CronJob/team-a/backup': '',
      'batch/Job/team-a/backup-28123456': 'batch/CronJob/team-a/backup',
      'Pod/team-a/backup-28123456-x7k2p': 'batch/Job/team-a/backup-28123456',
    });
    // A kind that owns nothing here gets no inferred children, and a
    // namespace boundary is never crossed.
    expect(placement([d('ConfigMap/team-a/web'), d('Pod/team-a/web-abcde'), d('apps/ReplicaSet/team-b/web-abcde'), d('Pod/team-a/web-abcde-fghij')])).toEqual({
      'ConfigMap/team-a/web': '',
      'Pod/team-a/web-abcde': '',
      'apps/ReplicaSet/team-b/web-abcde': '',
      'Pod/team-a/web-abcde-fghij': '',
    });
  });

  it('parses the engine object strings', () => {
    expect(parseObject('apps/Deployment/team-a/web')).toMatchObject({ group: 'apps', kind: 'Deployment', namespace: 'team-a', name: 'web', parsed: true });
    expect(parseObject('Pod/team-a/web-1')).toMatchObject({ group: '', kind: 'Pod', namespace: 'team-a', name: 'web-1', parsed: true });
    expect(parseObject('PersistentVolume//pv-1')).toMatchObject({ kind: 'PersistentVolume', namespace: '', name: 'pv-1', parsed: true });
    expect(parseObject('nope').parsed).toBe(false);
    expect(parseObject('/team-a/x').parsed).toBe(false);
  });

  it('no effect is lost when the owner chain cannot be inferred', () => {
    const effects = [
      { kind: 'destroys', object: 'Pod/team-b/lonely' },
      { kind: 'destroys', object: 'example.com/Widget/team-b/w1' },
      { kind: 'replaced', object: 'apps/ReplicaSet/team-b/api-5f6' },
      // Same object twice with different effects: one node, both effects.
      { kind: 'destroys', object: 'Pod/team-b/api-5f6-zzzzz' },
      { kind: 'orphans', object: 'Pod/team-b/api-5f6-zzzzz' },
      { kind: 'destroys', object: 'Namespace//team-b' },
      { kind: 'destroys', object: 'not an object string' },
      { kind: 'destroys', object: 'a/b/c/d/e' },
      { kind: 'destroys', object: '' },
      { kind: 'something-new', object: 'PersistentVolume//pv-9', explanation: 'pvc/nope is bound to pv/pv-9' },
      // Stored JSON gone odd: a non-string object is kept, unrecognised.
      { kind: 'destroys', object: 42 as unknown as string },
    ];
    // A null entry has nothing to show; it must not crash the tree.
    const withNull = [...effects, null as unknown as Effect];
    // Every effect is somewhere in the tree.
    const groups = buildTree(withNull);
    let n = 0;
    const walk = (nodes: ReturnType<typeof buildTree>[number]['roots']) => {
      for (const x of nodes) {
        n += x.effects.length;
        walk(x.children);
      }
    };
    for (const g of groups) walk(g.roots);
    expect(n).toBe(effects.length);
    const at = placement(withNull.filter((e) => e && typeof e.object === 'string') as Effect[]);
    expect(at['Pod/team-b/lonely']).toBe('');
    expect(at['example.com/Widget/team-b/w1']).toBe('');
    expect(at['Pod/team-b/api-5f6-zzzzz']).toBe('apps/ReplicaSet/team-b/api-5f6');
    // Unparseable strings are kept, verbatim, in their own group, last.
    const other = groups[groups.length - 1];
    expect(other.key).toBe(UNRECOGNISED);
    expect(other.roots.map((r) => r.ref.name)).toEqual(expect.arrayContaining(['not an object string', 'a/b/c/d/e']));
  });
});
