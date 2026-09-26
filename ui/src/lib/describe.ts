// Turns a Kubernetes request into one plain-English sentence (spec §4/§5).
// No regex on untrusted input beyond simple equality: a name is only ever
// concatenated as a literal string, never matched against or interpolated
// into a pattern. Spec §5: any unrecognised verb/resource/subresource
// pairing renders literally — nothing is ever hidden behind a sentence
// that quietly ignores part of the request.

export type Described = { sentence: string; target: string; resourceNoun: string };
export type Requestish = { verb: string; group?: string; resource: string; subresource?: string; namespace: string; name: string };

// targetOf: the display identifier for a namespace/name pair. Unlike
// friction's typedTarget, this may be empty — describe() falls back to
// other words when there is nothing to point at.
export function targetOf(r: { namespace: string; name: string }): string {
  if (r.namespace && r.name) return `${r.namespace}/${r.name}`;
  return r.name || '';
}

// [singular, plural]. A Map, not an object literal: a plain object's
// lookup reads the prototype chain, so a resource literally named
// "constructor" or "__proto__" — both valid CRD plurals — would throw or
// return a function instead of undefined. An unlisted resource falls
// back to its own raw string for both forms (the "unknown resource"
// case).
const NOUNS = new Map<string, [string, string]>([
  ['pods', ['pod', 'pods']],
  ['deployments', ['deployment', 'deployments']],
  ['statefulsets', ['stateful set', 'stateful sets']],
  ['daemonsets', ['daemon set', 'daemon sets']],
  ['replicasets', ['replica set', 'replica sets']],
  ['jobs', ['job', 'jobs']],
  ['cronjobs', ['cron job', 'cron jobs']],
  ['services', ['service', 'services']],
  ['configmaps', ['config map', 'config maps']],
  ['secrets', ['secret', 'secrets']],
  ['persistentvolumeclaims', ['volume claim', 'volume claims']],
  ['persistentvolumes', ['volume', 'volumes']],
  ['namespaces', ['namespace', 'namespaces']],
  ['ingresses', ['ingress', 'ingresses']],
  ['networkpolicies', ['network policy', 'network policies']],
  ['poddisruptionbudgets', ['disruption budget', 'disruption budgets']],
  ['serviceaccounts', ['service account', 'service accounts']],
  ['roles', ['role', 'roles']],
  ['rolebindings', ['role binding', 'role bindings']],
  ['clusterroles', ['cluster role', 'cluster roles']],
  ['clusterrolebindings', ['cluster role binding', 'cluster role bindings']],
  ['certificatesigningrequests', ['certificate signing request', 'certificate signing requests']],
  ['nodes', ['node', 'nodes']],
  ['leases', ['lease', 'leases']],
  ['events', ['event', 'events']],
]);

function nouns(resource: string): [string, string] {
  return NOUNS.get(resource) ?? [resource, resource];
}

// splitResource: the admin API joins a subresource into resource
// ("pods/exec") rather than sending it separately (internal/admin/api.go,
// summarize()) — an ApprovalSummary has no subresource field at all, and
// no group either. When our own callers already split them (tests, and
// anywhere still building a Requestish by hand), that split is kept as
// given. Plain indexOf: no regex is used on a value that can hold
// untrusted request data.
function splitResource(resource: string, subresource: string | undefined): { resource: string; subresource?: string } {
  if (subresource !== undefined) return { resource, subresource };
  const i = resource.indexOf('/');
  if (i === -1) return { resource };
  return { resource: resource.slice(0, i), subresource: resource.slice(i + 1) };
}

// RBAC resources that grant access rather than merely change state, plus
// the two other ways a request hands out access: minting a service
// account token, and approving a certificate signing request. Only a
// write verb is framed this way — reading or deleting one of these is
// still a plain read/delete sentence below, since only a create/update
// actually grants something.
const AUTHORITY_GROUP = 'rbac.authorization.k8s.io';
const RBAC_RESOURCES = new Set(['clusterrolebindings', 'rolebindings', 'clusterroles', 'roles']);
const WRITE_VERBS = new Set(['create', 'update', 'patch']);

function isAuthority(resource: string, subresource: string | undefined, group: string | undefined, verb: string): boolean {
  if (!WRITE_VERBS.has(verb)) return false;
  // ApprovalSummary carries no group at all: an undefined group still
  // counts as RBAC for these four resource names, matching the server,
  // which classes every rbac.authorization.k8s.io write as AUTHORITY.
  // This fails toward the stronger wording rather than the calmer one.
  if (RBAC_RESOURCES.has(resource) && (group === undefined || group === AUTHORITY_GROUP)) return true;
  if (resource === 'serviceaccounts' && subresource === 'token') return true;
  return resource === 'certificatesigningrequests' && subresource === 'approval';
}

// literalFallback: an unrecognized verb/resource/subresource combination,
// or one missing the name or noun a sentence needs, still reads as
// something concrete — never a blank confirm dialog, and never a
// sentence that silently drops part of the request.
function literalFallback(verb: string, resource: string, subresource: string | undefined, r: { namespace: string; name: string }): string {
  const resourcePart = resource ? resource + (subresource ? `/${subresource}` : '') : '';
  const parts = [verb, resourcePart].filter(Boolean);
  const tgt = targetOf(r);
  const full = [...parts, tgt].filter(Boolean).join(' ');
  return full || 'Unknown request';
}

export function describe(r: Requestish): Described {
  const { resource, subresource } = splitResource(r.resource, r.subresource);
  const [singular, plural] = nouns(resource);
  const target = targetOf(r);
  const hasNoun = singular !== '';
  const hasName = r.name !== '';
  const fallback = () => literalFallback(r.verb, resource, subresource, r);

  let sentence: string;

  if (isAuthority(resource, subresource, r.group, r.verb)) {
    sentence = hasNoun && hasName ? `Grant access with the ${singular} ${r.name}` : fallback();
  } else if (subresource) {
    // Only these subresources ever get their own sentence. Any other
    // pairing — including a recognised one on the wrong verb, such as
    // `scale` read with `get` rather than changed with `patch` — falls
    // through to the literal fallback instead of guessing.
    switch (subresource) {
      case 'scale':
        sentence = (r.verb === 'patch' || r.verb === 'update') && hasNoun && hasName ? `Scale the ${singular} ${r.name}` : fallback();
        break;
      case 'exec':
        sentence = hasName ? `Run a command in ${r.name}` : fallback();
        break;
      case 'attach':
        sentence = hasName ? `Attach to ${r.name}` : fallback();
        break;
      case 'portforward':
        sentence = hasName ? `Forward a port to ${r.name}` : fallback();
        break;
      case 'ephemeralcontainers':
        sentence = hasName ? `Add a debug container to ${r.name}` : fallback();
        break;
      case 'log':
        sentence = hasName ? `Read the logs of ${r.name}` : fallback();
        break;
      default:
        sentence = fallback();
    }
  } else {
    switch (r.verb) {
      case 'delete':
        sentence = hasNoun && hasName ? `Delete the ${singular} ${r.name}` : fallback();
        break;
      case 'deletecollection':
        sentence = hasNoun ? (r.namespace ? `Delete every ${singular} in ${r.namespace}` : `Delete every ${singular}`) : fallback();
        break;
      case 'create':
        if (!hasNoun) sentence = fallback();
        else if (hasName) sentence = `Create the ${singular} ${r.name}`;
        // No name (a generateName create): still true without one, so
        // say what kind and where rather than drop to the fallback.
        else sentence = `Create a ${singular}${r.namespace ? ` in ${r.namespace}` : ''}`;
        break;
      case 'update':
      case 'patch':
        sentence = hasNoun && hasName ? `Change the ${singular} ${r.name}` : fallback();
        break;
      case 'get':
        sentence = hasNoun ? (hasName ? `Read the ${singular} ${r.name}` : `Read the list of ${plural}`) : fallback();
        break;
      case 'list':
        sentence = plural ? `Read the list of ${plural}` : fallback();
        break;
      case 'watch':
        sentence = plural ? `Watch ${plural}` : fallback();
        break;
      default:
        sentence = fallback();
    }
  }

  return { sentence, target, resourceNoun: singular };
}
