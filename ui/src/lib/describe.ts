// Turns a Kubernetes request into one plain-English sentence (spec §4/§5).
// No regex on untrusted input beyond simple equality: a name is only ever
// concatenated as a literal string, never matched against or interpolated
// into a pattern.

export type Described = { sentence: string; target: string; resourceNoun: string };
export type Requestish = { verb: string; group?: string; resource: string; subresource?: string; namespace: string; name: string };

// targetOf: the display identifier for a namespace/name pair. Unlike
// friction's typedTarget, this may be empty — describe() falls back to
// other words when there is nothing to point at.
export function targetOf(r: { namespace: string; name: string }): string {
  if (r.namespace && r.name) return `${r.namespace}/${r.name}`;
  return r.name || '';
}

// [singular, plural]. An unlisted resource falls back to its own raw
// string for both forms (Step 6's "unknown resource" case).
const NOUNS: Record<string, [string, string]> = {
  pods: ['pod', 'pods'],
  deployments: ['deployment', 'deployments'],
  statefulsets: ['stateful set', 'stateful sets'],
  daemonsets: ['daemon set', 'daemon sets'],
  replicasets: ['replica set', 'replica sets'],
  jobs: ['job', 'jobs'],
  cronjobs: ['cron job', 'cron jobs'],
  services: ['service', 'services'],
  configmaps: ['config map', 'config maps'],
  secrets: ['secret', 'secrets'],
  persistentvolumeclaims: ['volume claim', 'volume claims'],
  persistentvolumes: ['volume', 'volumes'],
  namespaces: ['namespace', 'namespaces'],
  ingresses: ['ingress', 'ingresses'],
  networkpolicies: ['network policy', 'network policies'],
  poddisruptionbudgets: ['disruption budget', 'disruption budgets'],
  serviceaccounts: ['service account', 'service accounts'],
  roles: ['role', 'roles'],
  rolebindings: ['role binding', 'role bindings'],
  clusterroles: ['cluster role', 'cluster roles'],
  clusterrolebindings: ['cluster role binding', 'cluster role bindings'],
  nodes: ['node', 'nodes'],
  leases: ['lease', 'leases'],
  events: ['event', 'events'],
};

function nouns(resource: string): [string, string] {
  return NOUNS[resource] ?? [resource, resource];
}

// RBAC resources that grant access rather than merely change state. Only
// a write verb is framed this way: reading or deleting one of these is
// still a plain read/delete sentence below, since only a create/update
// actually hands out more access.
const AUTHORITY_GROUP = 'rbac.authorization.k8s.io';
const AUTHORITY_RESOURCES = new Set(['clusterrolebindings', 'rolebindings', 'clusterroles', 'roles']);
const WRITE_VERBS = new Set(['create', 'update', 'patch']);

function isAuthority(r: Requestish): boolean {
  if (!WRITE_VERBS.has(r.verb)) return false;
  if (r.group === AUTHORITY_GROUP && AUTHORITY_RESOURCES.has(r.resource)) return true;
  return r.resource === 'serviceaccounts' && r.subresource === 'token';
}

// literalFallback: an unrecognized verb/resource/subresource combination
// still reads as something, never as a blank confirm dialog.
function literalFallback(r: Requestish): string {
  const resourcePart = r.resource ? r.resource + (r.subresource ? `/${r.subresource}` : '') : '';
  const parts = [r.verb, resourcePart].filter(Boolean);
  const tgt = targetOf(r);
  const full = [...parts, tgt].filter(Boolean).join(' ');
  return full || 'Unknown request';
}

export function describe(r: Requestish): Described {
  const [singular, plural] = nouns(r.resource);
  const target = targetOf(r);
  let sentence: string;

  if (isAuthority(r)) {
    sentence = `Grant access with the ${singular} ${r.name}`;
  } else if (r.subresource === 'scale') {
    sentence = `Scale the ${singular} ${r.name}`;
  } else if (r.subresource === 'exec') {
    sentence = `Run a command in ${r.name}`;
  } else if (r.subresource === 'attach') {
    sentence = `Attach to ${r.name}`;
  } else if (r.subresource === 'portforward') {
    sentence = `Forward a port to ${r.name}`;
  } else if (r.subresource === 'ephemeralcontainers') {
    sentence = `Add a debug container to ${r.name}`;
  } else if (r.subresource === 'log') {
    sentence = `Read the logs of ${r.name}`;
  } else if (r.verb === 'delete') {
    sentence = `Delete the ${singular} ${r.name}`;
  } else if (r.verb === 'deletecollection') {
    sentence = r.namespace ? `Delete every ${singular} in ${r.namespace}` : `Delete every ${singular}`;
  } else if (r.verb === 'create') {
    sentence = `Create the ${singular} ${r.name}`;
  } else if (r.verb === 'update' || r.verb === 'patch') {
    sentence = `Change the ${singular} ${r.name}`;
  } else if (r.verb === 'get') {
    sentence = r.name ? `Read the ${singular} ${r.name}` : `Read the list of ${plural}`;
  } else if (r.verb === 'list') {
    sentence = `Read the list of ${plural}`;
  } else if (r.verb === 'watch') {
    sentence = `Watch ${plural}`;
  } else {
    sentence = literalFallback(r);
  }

  return { sentence, target, resourceNoun: singular };
}
