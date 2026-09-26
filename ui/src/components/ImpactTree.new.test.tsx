import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ImpactTree from './ImpactTree.new';
import { buildTree } from './ImpactTree';
import { renderWithMotion } from '../test/motion';
import { deploymentImpact, impact } from '../test/fixtures';
import type { Effect } from '../api';

afterEach(cleanup);

const EVIL = '<img src=x onerror=alert(1)>';

// node finds the tree item for one object by its engine object string.
function node(root: HTMLElement, object: string): HTMLElement {
  const el = Array.from(root.querySelectorAll<HTMLElement>('[data-object]')).find((e) => e.dataset.object === object);
  if (!el) throw new Error(`no tree node for ${object}`);
  return el;
}

// row is the clickable line of a tree item (not its children).
const row = (item: HTMLElement) => item.querySelector<HTMLElement>(':scope > .itree-row')!;

// expandAll opens every collapsed branch, one click at a time, until
// nothing is left closed: collapsed children are not in the page at all.
async function expandAll(container: HTMLElement) {
  for (let i = 0; i < 200; i++) {
    const closed = container.querySelector<HTMLElement>('[role="treeitem"][aria-expanded="false"]');
    if (!closed) return;
    await userEvent.click(row(closed));
  }
  throw new Error('tree never finished expanding');
}

const items = (root: HTMLElement) => Array.from(root.querySelectorAll<HTMLElement>('[role="treeitem"]'));
const label = (item: HTMLElement) => document.getElementById(item.getAttribute('aria-labelledby')!)!.textContent;

describe('ImpactTree (new)', () => {
  it('nests pods under their deployment and marks destroyed data', async () => {
    const { container } = renderWithMotion(<ImpactTree impact={deploymentImpact()} />);
    await expandAll(container);

    const ns = container.querySelector<HTMLElement>('[data-namespace="team-a"]')!;
    expect(ns.getAttribute('aria-level')).toBe('1');
    const dep = node(ns, 'apps/Deployment/team-a/web');
    const rs = node(dep, 'apps/ReplicaSet/team-a/web-7d9f8c');
    expect(dep.getAttribute('aria-level')).toBe('2');
    expect(rs.getAttribute('aria-level')).toBe('3');
    expect(node(rs, 'Pod/team-a/web-7d9f8c-abcde').getAttribute('aria-level')).toBe('4');
    expect(node(rs, 'Pod/team-a/web-7d9f8c-fghij')).toBeTruthy();
    expect(within(row(dep)).getByText('3 below')).toBeTruthy();
    expect(within(row(rs)).getByText('2 below')).toBeTruthy();

    // The cluster-scoped volume hangs off the claim bound to it.
    const pvc = node(ns, 'PersistentVolumeClaim/team-a/data');
    const pv = node(pvc, 'PersistentVolume//pv-1');
    expect(pv.classList.contains('data-destroyed')).toBe(true);
    expect(within(row(pv)).getByText('data destroyed').className).toContain('tone-danger');
    expect(pvc.classList.contains('data-destroyed')).toBe(false);
    expect(dep.querySelectorAll('.data-destroyed')).toHaveLength(0);
    expect(within(row(dep)).getByText('deleted')).toBeTruthy();

    const unknown = Array.from(container.querySelectorAll<HTMLElement>('.data-unknown'));
    expect(unknown).toHaveLength(1);
    expect(within(row(unknown[0])).getByText('data fate unknown').className).toContain('tone-caution');
    expect(within(row(unknown[0])).getByText('scratch')).toBeTruthy();

    const emptied = container.querySelector<HTMLElement>('[aria-label="Services left with no backends"]')!;
    expect(within(emptied).getByText('web')).toBeTruthy();
    expect(within(emptied).queryByText('api')).toBeNull();
    const pdb = container.querySelector<HTMLElement>('[aria-label="Disruption budgets broken"]')!;
    expect(within(pdb).getByText('team-a/web-pdb')).toBeTruthy();

    expect(container.querySelectorAll('[data-effect]')).toHaveLength(deploymentImpact().effects!.length);
  });

  it('no effect is lost when the owner chain cannot be inferred', async () => {
    const effects = [
      { kind: 'destroys', object: 'Pod/team-b/lonely' },
      { kind: 'destroys', object: 'example.com/Widget/team-b/w1' },
      { kind: 'replaced', object: 'apps/ReplicaSet/team-b/api-5f6' },
      { kind: 'destroys', object: 'Pod/team-b/api-5f6-zzzzz' },
      { kind: 'orphans', object: 'Pod/team-b/api-5f6-zzzzz' },
      { kind: 'destroys', object: 'Namespace//team-b' },
      { kind: 'destroys', object: 'not an object string' },
      { kind: 'destroys', object: 'a/b/c/d/e' },
      { kind: 'destroys', object: '' },
      { kind: 'something-new', object: 'PersistentVolume//pv-9', explanation: 'pvc/nope is bound to pv/pv-9' },
      { kind: 'destroys', object: 42 as unknown as string },
    ];
    const withNull = [...effects, null as unknown as Effect];
    const { container } = renderWithMotion(<ImpactTree impact={impact({ effects: withNull, dataDestroyed: 0 })} />);
    // The group of things that could not be read is open from the start.
    const other = container.querySelector<HTMLElement>('[data-namespace="(unrecognised)"]')!;
    expect(label(other)).toContain('Unrecognised');
    expect(other.getAttribute('aria-expanded')).toBe('true');
    expect(within(other).getByText('not an object string')).toBeTruthy();
    expect(within(other).getByText('a/b/c/d/e')).toBeTruthy();
    // An unknown effect kind shows its raw name, and its branch is open.
    expect(within(container).getByText('something-new')).toBeTruthy();

    await expandAll(container);
    expect(container.querySelectorAll('[data-effect]')).toHaveLength(effects.length);
    const nsB = container.querySelector<HTMLElement>('[data-namespace="team-b"]')!;
    expect(node(nsB, 'Pod/team-b/lonely')).toBeTruthy();
    expect(node(nsB, 'example.com/Widget/team-b/w1')).toBeTruthy();
    expect(node(node(nsB, 'apps/ReplicaSet/team-b/api-5f6'), 'Pod/team-b/api-5f6-zzzzz')).toBeTruthy();

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
  });

  // parents maps each rendered object to the object it was drawn under
  // ('' for the top of its namespace), read from the rendered tree.
  async function parents(effects: Effect[]) {
    const { container, unmount } = renderWithMotion(<ImpactTree impact={impact({ effects, dataDestroyed: 0 })} />);
    await expandAll(container);
    const where: Record<string, string> = {};
    for (const el of Array.from(container.querySelectorAll<HTMLElement>('[data-object]'))) {
      const up = el.parentElement!.closest<HTMLElement>('[data-object]');
      where[el.dataset.object!] = up ? up.dataset.object! : '';
    }
    unmount();
    return where;
  }
  const d = (object: string) => ({ kind: 'destroys', object });

  it('an owner is inferred only when the rest of the name has the controller shape', async () => {
    expect(await parents([d('apps/Deployment/team-a/web'), d('apps/ReplicaSet/team-a/web-api-7d9f8c6b5'), d('Pod/team-a/web-api-7d9f8c6b5-abcde')])).toEqual({
      'apps/Deployment/team-a/web': '',
      'apps/ReplicaSet/team-a/web-api-7d9f8c6b5': '',
      'Pod/team-a/web-api-7d9f8c6b5-abcde': 'apps/ReplicaSet/team-a/web-api-7d9f8c6b5',
    });
    expect(await parents([d('apps/StatefulSet/team-a/web'), d('Pod/team-a/web-api-7d9f8c6b5-abcde'), d('Pod/team-a/web-foo')])).toEqual({
      'apps/StatefulSet/team-a/web': '',
      'Pod/team-a/web-api-7d9f8c6b5-abcde': '',
      'Pod/team-a/web-foo': '',
    });
    expect(await parents([d('apps/ReplicaSet/team-a/web-7d9f8c6b5'), d('Pod/team-a/web-7d9f8c6b5-extra-abcde')])).toEqual({
      'apps/ReplicaSet/team-a/web-7d9f8c6b5': '',
      'Pod/team-a/web-7d9f8c6b5-extra-abcde': '',
    });
    expect(await parents([d('batch/CronJob/team-a/backup'), d('batch/Job/team-a/backup-db-28123456')])).toEqual({
      'batch/CronJob/team-a/backup': '',
      'batch/Job/team-a/backup-db-28123456': '',
    });
  });

  it('the controller shapes still nest', async () => {
    expect(
      await parents([
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
    expect(await parents([d('ConfigMap/team-a/web'), d('Pod/team-a/web-abcde'), d('apps/ReplicaSet/team-b/web-abcde'), d('Pod/team-a/web-abcde-fghij')])).toEqual({
      'ConfigMap/team-a/web': '',
      'Pod/team-a/web-abcde': '',
      'apps/ReplicaSet/team-b/web-abcde': '',
      'Pod/team-a/web-abcde-fghij': '',
    });
  });

  it('says when there are no effects', () => {
    const { container } = renderWithMotion(<ImpactTree impact={impact({ effects: [], dataDestroyed: 0 })} />);
    expect(within(container).getByText(/no objects are affected/i)).toBeTruthy();
    expect(within(container).queryByRole('tree')).toBeNull();
  });

  it('renders hostile names as text', async () => {
    const ns = EVIL.replace(/\//g, '');
    const { container } = renderWithMotion(
      <ImpactTree
        impact={impact({
          effects: [
            { kind: 'destroys-data', object: `Pod/${ns}/${ns}`, explanation: EVIL },
            { kind: EVIL, object: EVIL },
          ],
          endpointsLeft: { [EVIL]: 0 },
          pdbViolations: [EVIL],
        })}
      />,
    );
    await expandAll(container);
    expect(within(container).getAllByText(ns).length).toBeGreaterThan(0);
    expect(within(container).getAllByText(EVIL).length).toBeGreaterThanOrEqual(4);
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('[onerror]')).toBeNull();
    expect(container.innerHTML).toContain('&lt;img');
  });

  it('more than five pods collapse into Pod × N and expand', async () => {
    const pods = Array.from({ length: 47 }, (_, i) => d(`Pod/team-a/web-7d9f8c-${String(i).padStart(5, 'p')}`));
    const { container } = renderWithMotion(<ImpactTree impact={impact({ effects: [d('apps/ReplicaSet/team-a/web-7d9f8c'), ...pods], dataDestroyed: 0 })} />);
    // Everything here is a plain delete, so it all starts closed.
    await userEvent.click(row(container.querySelector<HTMLElement>('[data-namespace="team-a"]')!));
    const rs = node(container, 'apps/ReplicaSet/team-a/web-7d9f8c');
    await userEvent.click(row(rs));
    const bundle = within(rs).getByText('Pod × 47').closest<HTMLElement>('[role="treeitem"]')!;
    expect(bundle.getAttribute('aria-expanded')).toBe('false');
    expect(bundle.getAttribute('aria-level')).toBe('3');
    // Only the one line, not 47.
    expect(rs.querySelectorAll('[data-object^="Pod/"]')).toHaveLength(0);
    await userEvent.click(row(bundle));
    expect(bundle.getAttribute('aria-expanded')).toBe('true');
    const shown = bundle.querySelectorAll<HTMLElement>('[data-object^="Pod/"]');
    expect(shown).toHaveLength(47);
    expect(shown[0].getAttribute('aria-level')).toBe('4');

    // Five of a kind stay as they are.
    cleanup();
    const five = pods.slice(0, 5);
    const again = renderWithMotion(<ImpactTree impact={impact({ effects: [d('apps/ReplicaSet/team-a/web-7d9f8c'), ...five], dataDestroyed: 0 })} />);
    await expandAll(again.container);
    expect(within(again.container).queryByText(/×/)).toBeNull();
    expect(again.container.querySelectorAll('[data-object^="Pod/"]')).toHaveLength(5);
  });

  it('branches with destroyed data start open, others closed', () => {
    const { container } = renderWithMotion(<ImpactTree impact={deploymentImpact()} />);
    const ns = container.querySelector<HTMLElement>('[data-namespace="team-a"]')!;
    expect(ns.getAttribute('aria-expanded')).toBe('true');
    // The claim holds the destroyed volume: open, and the volume is shown.
    const pvc = node(ns, 'PersistentVolumeClaim/team-a/data');
    expect(pvc.getAttribute('aria-expanded')).toBe('true');
    expect(node(pvc, 'PersistentVolume//pv-1')).toBeTruthy();
    // The deployment only holds deletes: closed, its pods not drawn.
    const dep = node(ns, 'apps/Deployment/team-a/web');
    expect(dep.getAttribute('aria-expanded')).toBe('false');
    expect(dep.querySelector('[data-object]')).toBeNull();
    // The unbound claim whose fate is unknown opens its group.
    const cluster = container.querySelector<HTMLElement>('[data-namespace="(cluster-scoped)"]')!;
    expect(cluster.getAttribute('aria-expanded')).toBe('true');

    // Nothing alarming anywhere: every branch starts closed.
    cleanup();
    const calm = renderWithMotion(<ImpactTree impact={impact({ effects: [d('apps/Deployment/team-a/web'), d('apps/ReplicaSet/team-a/web-7d9f8c')], dataDestroyed: 0 })} />);
    const branches = calm.container.querySelectorAll('[aria-expanded]');
    expect(branches.length).toBeGreaterThan(0);
    for (const b of Array.from(branches)) expect(b.getAttribute('aria-expanded')).toBe('false');
  });

  it('arrow keys, home, end and star follow the tree pattern', async () => {
    const effects = [
      d('apps/Deployment/team-a/web'),
      d('apps/ReplicaSet/team-a/web-7d9f8c'),
      d('Pod/team-a/web-7d9f8c-abcde'),
      d('ConfigMap/team-a/settings'),
      d('apps/Deployment/team-a/api'),
      d('apps/ReplicaSet/team-a/api-5f6d7c'),
      d('ConfigMap/team-b/other'),
    ];
    renderWithMotion(<ImpactTree impact={impact({ effects, dataDestroyed: 0 })} />);
    const tree = screen.getByRole('tree');
    const focused = () => label(document.activeElement as HTMLElement);
    // One tab stop: the first item.
    const tabbable = items(tree).filter((i) => i.tabIndex === 0);
    expect(tabbable).toHaveLength(1);
    await userEvent.tab();
    expect(focused()).toContain('team-a');

    await userEvent.keyboard('{ArrowDown}');
    expect(focused()).toContain('team-b');
    await userEvent.keyboard('{ArrowUp}');
    expect(focused()).toContain('team-a');
    // Right opens a closed branch, then steps into it.
    await userEvent.keyboard('{ArrowRight}');
    expect(document.activeElement!.getAttribute('aria-expanded')).toBe('true');
    expect(focused()).toContain('team-a');
    await userEvent.keyboard('{ArrowRight}');
    expect(focused()).toContain('web');
    // Left on a closed child goes to its parent; on an open one, closes it.
    await userEvent.keyboard('{ArrowLeft}');
    expect(focused()).toContain('team-a');
    await userEvent.keyboard('{ArrowLeft}');
    expect(document.activeElement!.getAttribute('aria-expanded')).toBe('false');

    await userEvent.keyboard('{End}');
    expect(focused()).toContain('team-b');
    await userEvent.keyboard('{Home}');
    expect(focused()).toContain('team-a');

    // Star opens every sibling of the focused item, and does not move.
    await userEvent.keyboard('*');
    expect(focused()).toContain('team-a');
    for (const g of items(tree).filter((i) => i.getAttribute('aria-level') === '1')) expect(g.getAttribute('aria-expanded')).toBe('true');
    await userEvent.keyboard('{ArrowRight}');
    expect(focused()).toContain('web');
    await userEvent.keyboard('*');
    const level2 = items(tree).filter((i) => i.getAttribute('aria-level') === '2' && i.hasAttribute('aria-expanded'));
    expect(level2.length).toBe(2);
    for (const b of level2) expect(b.getAttribute('aria-expanded')).toBe('true');
    // Still one tab stop, and it follows focus.
    expect(items(tree).filter((i) => i.tabIndex === 0)).toEqual([document.activeElement]);
  });

  it('every item has a level and expanded state', async () => {
    const { container } = renderWithMotion(<ImpactTree impact={deploymentImpact()} />);
    await expandAll(container);
    const tree = screen.getByRole('tree');
    const all = items(tree);
    expect(all.length).toBeGreaterThan(8);
    for (const it of all) {
      expect(Number(it.getAttribute('aria-level'))).toBeGreaterThanOrEqual(1);
      // A branch says whether it is open; a leaf has no such state.
      const group = it.querySelector(':scope > [role="group"]');
      if (group) expect(it.getAttribute('aria-expanded')).toBe('true');
      else expect(it.hasAttribute('aria-expanded')).toBe(false);
      // Named by its own line, not by everything nested under it.
      expect(label(it)).toBeTruthy();
    }
    // A child's level is its parent's plus one.
    for (const g of Array.from(tree.querySelectorAll<HTMLElement>('[role="group"]'))) {
      const parent = g.closest<HTMLElement>('[role="treeitem"]')!;
      for (const c of Array.from(g.querySelectorAll<HTMLElement>(':scope > [role="treeitem"]'))) {
        expect(Number(c.getAttribute('aria-level'))).toBe(Number(parent.getAttribute('aria-level')) + 1);
      }
    }
  });
});
