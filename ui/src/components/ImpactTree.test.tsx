import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ImpactTree, { buildTree, parseObject } from './ImpactTree';
import { deploymentImpact, impact } from '../test/fixtures';

afterEach(cleanup);

// node finds the tree item for one object by its engine object string.
function node(root: HTMLElement, object: string): HTMLElement {
  const el = Array.from(root.querySelectorAll<HTMLElement>('[data-object]')).find((e) => e.dataset.object === object);
  if (!el) throw new Error(`no tree node for ${object}`);
  return el;
}

describe('ImpactTree', () => {
  it('impact tree nests pods under their deployment and marks destroyed data', () => {
    const { container } = render(<ImpactTree impact={deploymentImpact()} />);

    const ns = container.querySelector<HTMLElement>('[data-namespace="team-a"]')!;
    expect(ns).toBeTruthy();
    const dep = node(ns, 'apps/Deployment/team-a/web');
    const rs = node(dep, 'apps/ReplicaSet/team-a/web-7d9f8c');
    // Both pods sit inside the ReplicaSet, which sits inside the Deployment.
    expect(node(rs, 'Pod/team-a/web-7d9f8c-abcde')).toBeTruthy();
    expect(node(rs, 'Pod/team-a/web-7d9f8c-fghij')).toBeTruthy();
    // Counts per node: everything below it.
    expect(within(dep).getAllByText('3 below')[0]).toBeTruthy();
    expect(within(rs).getByText('2 below')).toBeTruthy();

    // The cluster-scoped volume hangs off the claim bound to it, and it is
    // the one marked as destroying data.
    const pvc = node(ns, 'PersistentVolumeClaim/team-a/data');
    const pv = node(pvc, 'PersistentVolume//pv-1');
    expect(pv.classList.contains('data-destroyed')).toBe(true);
    expect(within(pv).getByText('destroys data')).toBeTruthy();
    expect(pvc.classList.contains('data-destroyed')).toBe(false);
    expect(dep.querySelectorAll(':scope .data-destroyed')).toHaveLength(0);

    // An unbound claim's fate is not known: marked, not silently calm.
    const unknown = Array.from(container.querySelectorAll<HTMLElement>('.data-unknown'));
    expect(unknown).toHaveLength(1);
    expect(within(unknown[0]).getByText('data fate unknown')).toBeTruthy();
    expect(within(unknown[0]).getByText('scratch')).toBeTruthy();

    // Services with nothing left behind them, and broken budgets.
    const emptied = container.querySelector<HTMLElement>('[aria-label="Services left with no backends"]')!;
    expect(within(emptied).getByText('web')).toBeTruthy();
    expect(within(emptied).queryByText('api')).toBeNull();
    const pdb = container.querySelector<HTMLElement>('[aria-label="Disruption budgets broken"]')!;
    expect(within(pdb).getByText('team-a/web-pdb')).toBeTruthy();

    // Every effect is rendered exactly once.
    expect(container.querySelectorAll('[data-effect]')).toHaveLength(deploymentImpact().effects!.length);
  });

  it('nodes collapse and expand', async () => {
    const { container } = render(<ImpactTree impact={deploymentImpact()} />);
    const dep = node(container, 'apps/Deployment/team-a/web');
    const details = dep.querySelector('details')!;
    expect(details.open).toBe(true);
    await userEvent.click(details.querySelector('summary')!);
    expect(details.open).toBe(false);
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
    ];
    const { container } = render(<ImpactTree impact={impact({ effects, dataDestroyed: 0 })} />);
    expect(container.querySelectorAll('[data-effect]')).toHaveLength(effects.length);
    // The pod without an inferable owner is listed under its namespace.
    const nsB = container.querySelector<HTMLElement>('[data-namespace="team-b"]')!;
    expect(node(nsB, 'Pod/team-b/lonely')).toBeTruthy();
    expect(node(nsB, 'example.com/Widget/team-b/w1')).toBeTruthy();
    expect(node(node(nsB, 'apps/ReplicaSet/team-b/api-5f6'), 'Pod/team-b/api-5f6-zzzzz')).toBeTruthy();
    // Unparseable strings are kept, verbatim, in their own group.
    const other = container.querySelector<HTMLElement>('[data-namespace="(unrecognised)"]')!;
    expect(within(other).getByText('not an object string')).toBeTruthy();
    expect(within(other).getByText('a/b/c/d/e')).toBeTruthy();
    // An unknown effect kind shows its raw name.
    expect(within(container).getByText('something-new')).toBeTruthy();

    // And in the model: every effect is somewhere in the tree.
    const groups = buildTree(effects);
    let n = 0;
    const walk = (nodes: ReturnType<typeof buildTree>[number]['roots']) => {
      for (const x of nodes) {
        n += x.effects.length;
        walk(x.children);
      }
    };
    for (const g of groups) walk(g.roots);
    expect(n).toBe(effects.length);
  });

  it('parses the engine object strings', () => {
    expect(parseObject('apps/Deployment/team-a/web')).toMatchObject({ group: 'apps', kind: 'Deployment', namespace: 'team-a', name: 'web', parsed: true });
    expect(parseObject('Pod/team-a/web-1')).toMatchObject({ group: '', kind: 'Pod', namespace: 'team-a', name: 'web-1', parsed: true });
    expect(parseObject('PersistentVolume//pv-1')).toMatchObject({ kind: 'PersistentVolume', namespace: '', name: 'pv-1', parsed: true });
    expect(parseObject('nope').parsed).toBe(false);
    expect(parseObject('/team-a/x').parsed).toBe(false);
  });

  it('says when there are no effects', () => {
    const { container } = render(<ImpactTree impact={impact({ effects: [], dataDestroyed: 0 })} />);
    expect(within(container).getByText(/no objects are affected/i)).toBeTruthy();
  });
});
