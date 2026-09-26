import type { Effect, Impact } from '../api';
import { plural } from '../format';

// An effect's object is the engine's string: group/Kind/namespace/name,
// with the group left out for core objects and the namespace empty for
// cluster-scoped ones. Object names come from the cluster, which agents
// can write to, so everything here is shown as text and nothing parsed
// from it is trusted beyond choosing where in the tree to show it.
export type ObjectRef = { group: string; kind: string; namespace: string; name: string; raw: string; parsed: boolean };

export function parseObject(raw: string): ObjectRef {
  const p = raw.split('/');
  let ref: ObjectRef | undefined;
  if (p.length === 3) ref = { group: '', kind: p[0], namespace: p[1], name: p[2], raw, parsed: true };
  if (p.length === 4) ref = { group: p[0], kind: p[1], namespace: p[2], name: p[3], raw, parsed: true };
  if (ref && ref.kind !== '' && ref.name !== '') return ref;
  return { group: '', kind: '', namespace: '', name: raw, raw, parsed: false };
}

export type TreeNode = { key: string; ref: ObjectRef; effects: Effect[]; children: TreeNode[] };
export type TreeGroup = { key: string; label: string; roots: TreeNode[]; objects: number };

// Which kinds own which, by the naming Kubernetes' own controllers use: a
// ReplicaSet is named after its Deployment plus a hash, a Pod after its
// ReplicaSet (or StatefulSet, DaemonSet, Job) plus a suffix. The engine
// sends effects without ownerReferences, so this is only a display
// grouping; an object whose owner cannot be inferred stays at the top of
// its namespace, never dropped.
const OWNERS: Record<string, string[]> = {
  'apps/ReplicaSet': ['apps/Deployment'],
  Pod: ['apps/ReplicaSet', 'apps/StatefulSet', 'apps/DaemonSet', 'batch/Job'],
  'batch/Job': ['batch/CronJob'],
};

const gk = (r: ObjectRef) => (r.group ? `${r.group}/${r.kind}` : r.kind);

// sounding names the claim and volume in a volume effect's explanation:
// "pvc/<claim> is bound to pv/<volume> ...". PersistentVolumes are
// cluster-scoped, so this is the only link back to the claim.
const BOUND = /^pvc\/(\S+) is bound to pv\/(\S+)/;

export const CLUSTER = '(cluster-scoped)';
export const UNRECOGNISED = '(unrecognised)';

export function buildTree(effects: Effect[]): TreeGroup[] {
  const nodes = new Map<string, TreeNode>();
  const order: TreeNode[] = [];
  for (const ef of effects) {
    const ref = parseObject(ef.object);
    // Unparsed strings key on the raw text, parsed ones on their parts, so
    // the two can never merge into one node by accident.
    const key = ref.parsed ? `${gk(ref)}/${ref.namespace}/${ref.name}` : `\u0000${ef.object}`;
    let n = nodes.get(key);
    if (!n) {
      n = { key, ref, effects: [], children: [] };
      nodes.set(key, n);
      order.push(n);
    }
    n.effects.push(ef);
  }

  const claims = order.filter((n) => n.ref.parsed && gk(n.ref) === 'PersistentVolumeClaim' && n.ref.namespace !== '');
  const uniqueClaim = (name: string) => {
    const c = claims.filter((n) => n.ref.name === name);
    return c.length === 1 ? c[0] : undefined;
  };

  // An unbound claim's effect arrives without its namespace. When exactly
  // one claim of that name is in the tree, it is the same claim: its
  // effects join that node rather than floating among cluster objects.
  const merged = new Set<TreeNode>();
  for (const n of order) {
    if (!n.ref.parsed || n.ref.namespace !== '' || gk(n.ref) !== 'PersistentVolumeClaim') continue;
    const into = uniqueClaim(n.ref.name);
    if (into) {
      into.effects.push(...n.effects);
      merged.add(n);
    }
  }
  const live = order.filter((n) => !merged.has(n));

  const parentOf = (n: TreeNode): TreeNode | undefined => {
    if (!n.ref.parsed) return undefined;
    if (gk(n.ref) === 'PersistentVolume') {
      for (const ef of n.effects) {
        const m = BOUND.exec(ef.explanation ?? '');
        if (m && m[2] === n.ref.name) {
          const c = uniqueClaim(m[1]);
          if (c) return c;
        }
      }
      return undefined;
    }
    const owners = OWNERS[gk(n.ref)];
    if (!owners || n.ref.namespace === '') return undefined;
    let best: TreeNode | undefined;
    for (const p of live) {
      if (p === n || !p.ref.parsed || p.ref.namespace !== n.ref.namespace || !owners.includes(gk(p.ref))) continue;
      if (!n.ref.name.startsWith(p.ref.name + '-')) continue;
      // The longest matching name is the nearest owner: web-api-x belongs
      // to web-api, not to web.
      if (!best || p.ref.name.length > best.ref.name.length) best = p;
    }
    return best;
  };

  const groups = new Map<string, TreeGroup>();
  for (const n of live) {
    const parent = parentOf(n);
    if (parent) {
      parent.children.push(n);
      continue;
    }
    const gkey = !n.ref.parsed ? UNRECOGNISED : n.ref.namespace === '' ? CLUSTER : n.ref.namespace;
    let g = groups.get(gkey);
    if (!g) {
      g = { key: gkey, label: gkey, roots: [], objects: 0 };
      groups.set(gkey, g);
    }
    g.roots.push(n);
  }
  for (const g of groups.values()) g.objects = g.roots.reduce((s, n) => s + 1 + below(n), 0);

  // Namespaces alphabetically, then cluster-scoped objects, then anything
  // that could not be read as an object at all.
  const rank = (k: string) => (k === UNRECOGNISED ? 2 : k === CLUSTER ? 1 : 0);
  return [...groups.values()].sort((a, b) => rank(a.key) - rank(b.key) || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

function below(n: TreeNode): number {
  return n.children.reduce((s, c) => s + 1 + below(c), 0);
}

// Labels for sounding's and the engine's effect kinds. A kind not listed
// shows as its raw name: a new kind is information, not something to hide.
const KINDS: Record<string, { label: string; tone: string }> = {
  destroys: { label: 'deleted', tone: 'neutral' },
  'destroys-data': { label: 'destroys data', tone: 'danger' },
  'unknown-data-fate': { label: 'data fate unknown', tone: 'danger' },
  'detaches-data': { label: 'data kept, volume released', tone: 'warn' },
  replaced: { label: 'replaced', tone: 'warn' },
  grants: { label: 'grants access', tone: 'danger' },
  orphans: { label: 'orphaned', tone: 'warn' },
  retargets: { label: 'retargeted', tone: 'warn' },
  'scales-down': { label: 'scaled down', tone: 'warn' },
};

function kindOf(kind: string) {
  return Object.hasOwn(KINDS, kind) ? KINDS[kind] : { label: kind || 'unspecified', tone: 'neutral' };
}

function Node({ n }: { n: TreeNode }) {
  const destroys = n.effects.some((e) => e.kind === 'destroys-data');
  const unknown = n.effects.some((e) => e.kind === 'unknown-data-fate');
  const cls = ['tree-node', destroys ? 'data-destroyed' : '', unknown ? 'data-unknown' : ''].filter(Boolean).join(' ');
  const count = below(n);
  const label = (
    <span className="tree-label">
      {n.ref.parsed && <span className="tree-kind">{n.ref.kind}</span>}
      <span className="tree-name">{n.ref.name || '—'}</span>
      {n.effects.map((e, i) => (
        <span key={i} className={`chip chip-${kindOf(e.kind).tone}`} data-effect={e.kind}>
          {kindOf(e.kind).label}
        </span>
      ))}
      {count > 0 && <span className="tree-count">{count} below</span>}
    </span>
  );
  const why = n.effects.filter((e) => e.explanation);
  const explanations = why.length > 0 && (
    <ul className="tree-why">
      {why.map((e, i) => (
        <li key={i}>{e.explanation}</li>
      ))}
    </ul>
  );
  return (
    <li className={cls} data-object={n.ref.raw}>
      {n.children.length > 0 ? (
        <details open>
          <summary>{label}</summary>
          {explanations}
          <ul className="tree-children">
            {n.children.map((c) => (
              <Node key={c.key} n={c} />
            ))}
          </ul>
        </details>
      ) : (
        <div className="tree-leaf">
          {label}
          {explanations}
        </div>
      )}
    </li>
  );
}

export default function ImpactTree({ impact }: { impact: Impact }) {
  const effects = impact.effects ?? [];
  const groups = buildTree(effects);
  const emptied = Object.entries(impact.endpointsLeft ?? {})
    .filter(([, n]) => n === 0)
    .map(([svc]) => svc)
    .sort();
  const pdbs = impact.pdbViolations ?? [];

  return (
    <div className="impact-tree">
      {emptied.length > 0 && (
        <section className="tree-alert" aria-label="Services left with no backends">
          <h3>Services left with no backends</h3>
          <ul>
            {emptied.map((s) => (
              <li key={s} className="target">
                {s}
              </li>
            ))}
          </ul>
        </section>
      )}
      {pdbs.length > 0 && (
        <section className="tree-alert" aria-label="Disruption budgets broken">
          <h3>Disruption budgets broken</h3>
          <ul>
            {pdbs.map((p, i) => (
              <li key={i} className="target">
                {p}
              </li>
            ))}
          </ul>
        </section>
      )}

      {effects.length === 0 ? (
        <p className="dim">No objects are affected beyond the request itself.</p>
      ) : (
        <ul className="tree">
          {groups.map((g) => (
            <li key={g.key} className="tree-group" data-namespace={g.key}>
              <details open>
                <summary>
                  <span className="tree-label">
                    <span className="tree-ns">{g.label}</span>
                    <span className="tree-count">
                      {g.objects} {plural(g.objects, 'object')}
                    </span>
                  </span>
                </summary>
                <ul className="tree-children">
                  {g.roots.map((n) => (
                    <Node key={n.key} n={n} />
                  ))}
                </ul>
              </details>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
