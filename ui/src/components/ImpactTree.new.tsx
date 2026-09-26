import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import type { Effect, Impact } from '../api';
import { plural } from '../lib/format';
import { AnimatePresence, DUR, EASE, m, useIsPresent, useReducedMotion } from '../motion';
import { buildTree, CLUSTER, UNRECOGNISED, type TreeGroup, type TreeNode } from './ImpactTree';

// The owner inference (buildTree, parseObject) stays in the old module
// until Task 9 moves it here; this file only draws what it returns.

type Tone = 'danger' | 'caution';
type Marker = { label: string; tone?: Tone };

// Words for the engine's and sounding's effect kinds. A kind not listed
// shows as its raw name: a new kind is information, never hidden. A Map,
// so a kind literally named "constructor" is just an unknown kind.
const KINDS = new Map<string, Marker>([
  ['destroys', { label: 'deleted' }],
  ['deleted', { label: 'deleted' }],
  ['destroys-data', { label: 'data destroyed', tone: 'danger' }],
  ['unknown-data-fate', { label: 'data fate unknown', tone: 'caution' }],
  ['detaches-data', { label: 'data kept, volume released', tone: 'caution' }],
  ['replaced', { label: 'replaced', tone: 'caution' }],
  ['grants', { label: 'grants access', tone: 'danger' }],
  ['orphans', { label: 'orphaned', tone: 'caution' }],
  ['retargets', { label: 'retargeted', tone: 'caution' }],
  ['scales-down', { label: 'scaled down', tone: 'caution' }],
]);

// Stored JSON: a kind that is not a string still shows, as ''.
const kindOf = (e: Effect) => (typeof e.kind === 'string' ? e.kind : '');

function marker(e: Effect): Marker {
  const k = kindOf(e);
  return KINDS.get(k) ?? { label: k || 'unspecified' };
}

// alarming: an effect the approver must see without opening anything.
// Destroyed data, data whose fate nobody knows, and any kind this page
// has no words for (it could be either).
function alarming(e: Effect): boolean {
  const k = kindOf(e);
  return k === 'destroys-data' || k === 'unknown-data-fate' || !KINDS.has(k);
}

// More than this many same-kind siblings fold into one "Pod × 47" line,
// so a Deployment with a big ReplicaSet does not bury everything below it.
const BUNDLE_OVER = 5;

type Item = {
  id: string;
  level: number;
  children: Item[];
  // startOpen: the branch holds something alarming (or is the group of
  // unrecognised objects), so it is open before anyone asks.
  startOpen: boolean;
  alarm: boolean;
} & ({ type: 'group'; group: TreeGroup } | { type: 'node'; node: TreeNode } | { type: 'bundle'; kind: string; count: number });

const gk = (n: TreeNode) => (n.ref.group ? `${n.ref.group}/${n.ref.kind}` : n.ref.kind);

function below(n: TreeNode): number {
  return n.children.reduce((s, c) => s + 1 + below(c), 0);
}

function nodeItem(n: TreeNode, level: number): Item {
  const children = siblings(n.children, level + 1, `n:${n.key}`);
  const inside = children.some((c) => c.alarm);
  return { id: `n:${n.key}`, level, children, startOpen: inside, alarm: inside || n.effects.some(alarming), type: 'node', node: n };
}

// siblings turns one level of buildTree's nodes into items, folding each
// kind that has more than BUNDLE_OVER members into one expandable item at
// the place of its first member. Unparsed objects have no kind to fold by.
function siblings(nodes: TreeNode[], level: number, parent: string): Item[] {
  const count = new Map<string, number>();
  for (const n of nodes) if (n.ref.parsed) count.set(gk(n), (count.get(gk(n)) ?? 0) + 1);
  const out: Item[] = [];
  const bundled = new Set<string>();
  for (const n of nodes) {
    const k = n.ref.parsed ? gk(n) : '';
    if (!k || (count.get(k) ?? 0) <= BUNDLE_OVER) {
      out.push(nodeItem(n, level));
      continue;
    }
    if (bundled.has(k)) continue;
    bundled.add(k);
    const members = nodes.filter((x) => x.ref.parsed && gk(x) === k).map((x) => nodeItem(x, level + 1));
    const alarm = members.some((x) => x.alarm);
    out.push({ id: `b:${parent}:${k}`, level, children: members, startOpen: alarm, alarm, type: 'bundle', kind: n.ref.kind, count: members.length });
  }
  return out;
}

function groupItem(g: TreeGroup): Item {
  const children = siblings(g.roots, 2, `g:${g.key}`);
  const alarm = children.some((c) => c.alarm);
  return { id: `g:${g.key}`, level: 1, children, startOpen: alarm || g.key === UNRECOGNISED, alarm, type: 'group', group: g };
}

function groupLabel(key: string): ReactNode {
  if (key === UNRECOGNISED) return 'Unrecognised';
  if (key === CLUSTER) return 'Cluster-scoped';
  return <span className="mono">{key}</span>;
}

type Visible = { item: Item; parent?: Item };

export default function ImpactTree({ impact }: { impact: Impact }) {
  const base = useId();
  const reduce = useReducedMotion();
  const effects = impact.effects ?? [];
  const items = buildTree(effects).map(groupItem);

  // Only what someone changed is stored; everything else is its
  // startOpen. A reload that brings new objects opens them by the same
  // rule, and one that keeps them keeps what the approver did.
  const [toggled, setToggled] = useState<Map<string, boolean>>(() => new Map());
  const [focusId, setFocusId] = useState<string | null>(null);
  // keyboard: the last open or close came from a key. Disclosure then
  // happens at once; motion is for a pointer, never under the keys.
  const [keyboard, setKeyboard] = useState(false);
  const els = useRef(new Map<string, HTMLLIElement>());

  const isOpen = (it: Item) => it.children.length > 0 && (toggled.get(it.id) ?? it.startOpen);

  const visible: Visible[] = [];
  const walk = (list: Item[], parent?: Item) => {
    for (const item of list) {
      visible.push({ item, parent });
      if (isOpen(item)) walk(item.children, item);
    }
  };
  walk(items);
  // Roving tabindex: one tab stop. If the item that had it was folded
  // away, the first item takes it back.
  const current = visible.find((v) => v.item.id === focusId) ?? visible[0];

  function set(changes: [string, boolean][], byKey: boolean) {
    setKeyboard(byKey);
    setToggled((prev) => {
      const next = new Map(prev);
      for (const [id, open] of changes) next.set(id, open);
      return next;
    });
  }

  function moveTo(v: Visible | undefined) {
    if (!v) return;
    setFocusId(v.item.id);
    els.current.get(v.item.id)?.focus();
  }

  function onKeyDown(e: KeyboardEvent<HTMLUListElement>) {
    if (e.altKey || e.ctrlKey || e.metaKey) return;
    const el = (e.target as Element).closest<HTMLElement>('[role="treeitem"]');
    const i = visible.findIndex((v) => v.item.id === el?.dataset.id);
    if (i < 0) return;
    const { item, parent } = visible[i];
    const open = isOpen(item);
    switch (e.key) {
      case 'ArrowDown':
        moveTo(visible[i + 1]);
        break;
      case 'ArrowUp':
        moveTo(visible[i - 1]);
        break;
      case 'ArrowRight':
        if (item.children.length === 0) break;
        if (!open) set([[item.id, true]], true);
        else moveTo(visible[i + 1]);
        break;
      case 'ArrowLeft':
        if (open) set([[item.id, false]], true);
        else if (parent) moveTo(visible.find((v) => v.item === parent));
        break;
      case 'Home':
        moveTo(visible[0]);
        break;
      case 'End':
        moveTo(visible[visible.length - 1]);
        break;
      case 'Enter':
      case ' ':
        if (item.children.length === 0) break;
        set([[item.id, !open]], true);
        break;
      case '*': {
        const peers = parent ? parent.children : items;
        set(
          peers.filter((p) => p.children.length > 0).map((p) => [p.id, true]),
          true,
        );
        break;
      }
      default:
        return;
    }
    e.preventDefault();
  }

  function render(item: Item): ReactNode {
    const branch = item.children.length > 0;
    const open = isOpen(item);
    const labelId = `${base}-${item.id}`;
    let body: ReactNode;
    let own: Effect[] = [];
    const cls = ['itree-item'];
    const data: Record<string, string> = {};
    if (item.type === 'group') {
      const g = item.group;
      data['data-namespace'] = g.key;
      body = (
        <>
          <span className="itree-ns">{groupLabel(g.key)}</span>
          <span className="itree-count">
            {g.objects} {plural(g.objects, 'object')}
          </span>
        </>
      );
    } else if (item.type === 'bundle') {
      body = (
        <>
          <span className="itree-kind">{`${item.kind} × ${item.count}`}</span>
        </>
      );
    } else {
      const n = item.node;
      own = n.effects;
      data['data-object'] = n.ref.raw;
      if (own.some((e) => kindOf(e) === 'destroys-data')) cls.push('data-destroyed');
      if (own.some((e) => kindOf(e) === 'unknown-data-fate')) cls.push('data-unknown');
      const count = below(n);
      body = (
        <>
          {n.ref.parsed && <span className="itree-kind">{n.ref.kind}</span>}
          <span className="itree-name mono">{n.ref.name || '(no name)'}</span>
          {own.map((e, i) => {
            const mk = marker(e);
            return (
              <span key={i} className={`itree-marker${mk.tone ? ` tone-${mk.tone}` : ''}`} data-effect={kindOf(e)}>
                {mk.label}
              </span>
            );
          })}
          {count > 0 && <span className="itree-count">{count} below</span>}
        </>
      );
    }
    const why = own.filter((e) => typeof e.explanation === 'string' && e.explanation !== '');
    return (
      <li
        key={item.id}
        ref={(el) => {
          if (el) els.current.set(item.id, el);
          else els.current.delete(item.id);
        }}
        role="treeitem"
        aria-level={item.level}
        aria-expanded={branch ? open : undefined}
        aria-labelledby={labelId}
        tabIndex={current?.item.id === item.id ? 0 : -1}
        className={cls.join(' ')}
        data-id={item.id}
        onFocus={(e) => {
          // Focus set by a click, or by a screen reader's own cursor,
          // moves the tab stop with it.
          if (e.target === e.currentTarget) setFocusId(item.id);
        }}
        {...data}
      >
        <div
          className={branch ? 'itree-row itree-branch' : 'itree-row'}
          onClick={() => {
            setFocusId(item.id);
            els.current.get(item.id)?.focus();
            if (branch) set([[item.id, !open]], false);
          }}
        >
          <span className={branch ? (open ? 'itree-caret is-open' : 'itree-caret') : 'itree-caret is-leaf'} aria-hidden="true" />
          <span id={labelId} className="itree-label">
            {body}
          </span>
        </div>
        {why.length > 0 && (
          <ul className="itree-why">
            {why.map((e, i) => (
              <li key={i}>{e.explanation}</li>
            ))}
          </ul>
        )}
        {branch && (
          <AnimatePresence initial={false} custom={keyboard || reduce === true}>
            {open && (
              <Group key="group" instant={keyboard || reduce === true}>
                {item.children.map(render)}
              </Group>
            )}
          </AnimatePresence>
        )}
      </li>
    );
  }

  const emptied = Object.entries(impact.endpointsLeft ?? {})
    .filter(([, n]) => n === 0)
    .map(([svc]) => svc)
    .sort();
  const pdbs = impact.pdbViolations ?? [];

  return (
    <div className="itree-wrap">
      {emptied.length > 0 && (
        <section className="itree-alert" aria-label="Services left with no backends">
          <h3>Services left with no backends</h3>
          <ul>
            {emptied.map((s) => (
              <li key={s} className="mono">
                {s}
              </li>
            ))}
          </ul>
        </section>
      )}
      {pdbs.length > 0 && (
        <section className="itree-alert" aria-label="Disruption budgets broken">
          <h3>Disruption budgets broken</h3>
          <ul>
            {pdbs.map((p, i) => (
              <li key={i} className="mono">
                {p}
              </li>
            ))}
          </ul>
        </section>
      )}
      {effects.length === 0 ? (
        <p className="itree-none">No objects are affected beyond the request itself.</p>
      ) : (
        <ul className="itree" role="tree" aria-label="What would be affected" onKeyDown={onKeyDown}>
          {items.map(render)}
        </ul>
      )}
    </div>
  );
}

// The disclosure: height and opacity over DUR.disclose. The duration
// rides on AnimatePresence's custom value, not on the child's own props,
// because a closing group animates out with the props of its last render,
// taken before anyone knew whether a key or a click would close it.
const disclose = {
  closed: (instant: boolean) => ({ height: 0, opacity: 0, transition: { duration: instant ? 0 : DUR.disclose, ease: EASE } }),
  open: (instant: boolean) => ({ height: 'auto', opacity: 1, transition: { duration: instant ? 0 : DUR.disclose, ease: EASE } }),
};

// Group is one branch's children. On its way out it leaves the
// accessibility tree and takes no clicks or focus, so nothing folding
// away can still be reached for those 180ms.
function Group({ instant, children }: { instant: boolean; children: ReactNode }) {
  const present = useIsPresent();
  return (
    <m.ul
      role="group"
      className="itree-group"
      aria-hidden={present ? undefined : true}
      inert={!present}
      custom={instant}
      variants={disclose}
      initial="closed"
      animate="open"
      exit="closed"
    >
      {children}
    </m.ul>
  );
}
