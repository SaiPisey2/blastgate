// Types mirror the admin API's JSON exactly (api-contract.md): snake_case
// fields, RFC3339 time strings. Impact keeps the engine's own camelCase
// because it is the engine's stored JSON, passed through untouched.

export type Me = { name: string; csrf: string };

export type FeedRow = {
  id: number;
  at: string;
  kind: string; // "decision" | "result"
  request_id: string;
  session: string;
  human: string;
  agent: string;
  source: string;
  verb: string;
  group: string;
  resource: string;
  subresource: string;
  namespace: string;
  name: string;
  request_digest: string;
  class: string;
  measured: boolean;
  rule: string;
  decision: string;
  approval_id: string;
  status: number;
  outcome: string;
  latency_ms: number;
  snapshot: string;
  action?: unknown;
  impact?: unknown;
  labels?: unknown;
};

export type Effect = { kind: string; object: string; explanation?: string };

export type Impact = {
  class: string;
  measured: boolean;
  reason?: string;
  effects?: Effect[];
  dataDestroyed: number;
  endpointsLeft?: Record<string, number>;
  pdbViolations?: string[];
  sqlDetected: boolean;
  dryRunRejected: boolean;
  undo: string;
};

export type ApprovalSummary = {
  id: string;
  status: string;
  rule: string;
  human: string;
  agent: string;
  verb: string;
  resource: string;
  namespace: string;
  name: string;
  summary: string;
  // class and data_destroyed ride on the summary so a card's severity and
  // its typed confirmation never wait on (or depend on) a second request.
  class: string;
  data_destroyed: number;
  age_seconds: number;
  created: string;
  expires: string;
};

export type ApprovalDetail = ApprovalSummary & {
  action: unknown;
  impact: Impact;
  decided_by: string;
  decided: string;
};

export type Session = {
  id: string;
  human: string;
  agent: string;
  created: string;
  expires: string;
  state: 'active' | 'expired' | 'revoked';
};

export type BypassRow = {
  at: string;
  user: string;
  groups: string[];
  verb: string;
  group: string;
  resource: string;
  subresource: string;
  namespace: string;
  name: string;
  uid: string;
  dry_run: boolean;
};

export type ReplayChange = {
  at: string;
  request_id: string;
  verb: string;
  resource: string;
  namespace: string;
  name: string;
  rule_before: string;
  rule_after: string;
  decision_before: string;
  decision_after: string;
};

export type ReplayResult = {
  evaluated: number;
  changed: number;
  skipped: number;
  changes: ReplayChange[];
};

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

// The CSRF value lives only in this module's memory. It is not a secret
// the page could leak by storing it, but keeping it out of Web Storage
// means a reload always re-reads it from /api/me, i.e. from a live session.
let csrf = '';

export function setCSRF(value: string) {
  csrf = value;
}

const signedOutListeners = new Set<() => void>();

// onSignedOut registers a callback for "the server no longer knows this
// browser": any 401 outside the login call itself.
export function onSignedOut(fn: () => void): () => void {
  signedOutListeners.add(fn);
  return () => signedOutListeners.delete(fn);
}

function signedOut() {
  csrf = '';
  if (window.location.hash !== '#/login') window.location.hash = '#/login';
  signedOutListeners.forEach((fn) => fn());
}

export async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  // Only state-changing calls carry the CSRF value: the server demands it
  // there, and leaving it off GETs keeps it out of anything a GET might log.
  if (method !== 'GET' && method !== 'HEAD' && csrf !== '') headers['X-Blastgate-CSRF'] = csrf;
  const res = await fetch(path, {
    method,
    headers,
    // same-origin: the session cookie goes only to the server that set it.
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401 && path !== '/api/login') {
    signedOut();
    throw new ApiError(401, 'signed out');
  }
  const text = await res.text();
  let data: unknown = undefined;
  if (text !== '') {
    try {
      data = JSON.parse(text);
    } catch {
      throw new ApiError(res.status, 'unexpected response from the server');
    }
  }
  if (!res.ok) {
    const msg = data && typeof data === 'object' && 'error' in data ? String((data as { error: unknown }).error) : res.statusText;
    throw new ApiError(res.status, msg || `request failed (${res.status})`);
  }
  return data as T;
}

export const get = <T>(path: string) => request<T>('GET', path);
export const post = <T>(path: string, body?: unknown) => request<T>('POST', path, body);

export async function login(token: string): Promise<Me> {
  const me = await post<Me>('/api/login', { token });
  setCSRF(me.csrf);
  return me;
}

export async function whoami(): Promise<Me> {
  const me = await get<Me>('/api/me');
  setCSRF(me.csrf);
  return me;
}

export async function logout(): Promise<void> {
  try {
    await post('/api/logout');
  } finally {
    signedOut();
  }
}

// --- live stream -------------------------------------------------------

export type PendingEvent = { count: number; ids: string[] };
type StreamEvents = { audit: FeedRow; approvals: PendingEvent };
type Listener<K extends keyof StreamEvents> = (data: StreamEvents[K]) => void;

const listeners: { [K in keyof StreamEvents]: Set<Listener<K>> } = {
  audit: new Set(),
  approvals: new Set(),
};

export function subscribe<K extends keyof StreamEvents>(event: K, fn: Listener<K>): () => void {
  listeners[event].add(fn);
  return () => listeners[event].delete(fn);
}

// emit dispatches one stream event to subscribers. The EventSource below
// calls it; tests call it directly.
export function emit<K extends keyof StreamEvents>(event: K, data: StreamEvents[K]) {
  listeners[event].forEach((fn) => fn(data));
}

// Connection state of the stream, for the feed's Live indicator: a feed
// that says "Live" while disconnected is worse than no indicator.
export type StreamStatus = 'connecting' | 'live' | 'reconnecting' | 'offline';
let status: StreamStatus = 'offline';
const statusListeners = new Set<(s: StreamStatus) => void>();

export function streamStatus(): StreamStatus {
  return status;
}

export function onStreamStatus(fn: (s: StreamStatus) => void): () => void {
  statusListeners.add(fn);
  return () => statusListeners.delete(fn);
}

export function setStreamStatus(s: StreamStatus) {
  status = s;
  statusListeners.forEach((fn) => fn(s));
}

function parse(ev: MessageEvent): unknown {
  try {
    return JSON.parse(String(ev.data));
  } catch {
    return undefined;
  }
}

// openStream connects to /api/stream and feeds the hub. It returns a close
// function. Without EventSource (tests, very old browsers) it does nothing
// and the views still work from their initial fetches.
export function openStream(): () => void {
  if (typeof EventSource === 'undefined') return () => {};
  const es = new EventSource('/api/stream');
  setStreamStatus('connecting');
  es.onopen = () => setStreamStatus('live');
  es.addEventListener('audit', (ev) => {
    const row = parse(ev as MessageEvent);
    if (row && typeof row === 'object') emit('audit', row as FeedRow);
  });
  es.addEventListener('approvals', (ev) => {
    const d = parse(ev as MessageEvent) as Partial<PendingEvent> | undefined;
    if (!d) return;
    const ids = Array.isArray(d.ids) ? d.ids.map(String) : [];
    emit('approvals', { count: typeof d.count === 'number' ? d.count : ids.length, ids });
  });
  es.addEventListener('expired', () => {
    es.close();
    setStreamStatus('offline');
    signedOut();
  });
  es.onerror = () => {
    setStreamStatus(es.readyState === EventSource.CLOSED ? 'offline' : 'reconnecting');
    // EventSource retries by itself, except after a non-2xx answer such as
    // 401, when it gives up (CLOSED). Ask /api/me so a dead session lands
    // on the login screen instead of a silently frozen feed.
    if (es.readyState === EventSource.CLOSED) whoami().catch(() => {});
  };
  return () => {
    es.close();
    setStreamStatus('offline');
  };
}
