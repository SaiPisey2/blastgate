// @ts-expect-error -- this package has no @types/node; Vitest runs on Node.
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Waiting, { resetLastDecision } from './Waiting';
import { emit, setCSRF, type ApprovalSummary } from '../api';
import { announce } from '../components/Shell';
import { mockFetch, type Call } from '../test/fetch';
import { renderWithMotion } from '../test/motion';
import { setMedia } from '../test/media';
import { detail, ID1, ID2, impact, summary } from '../test/fixtures';

// The announcer is the shell's; a spy stands in so a test can count what
// the view asked it to say.
vi.mock('../components/Shell', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../components/Shell')>();
  return { ...mod, announce: vi.fn() };
});

afterEach(() => {
  cleanup();
  setCSRF('');
  vi.mocked(announce).mockClear();
  resetLastDecision();
});

const WIDE = '(min-width: 900px)';
const GONE = 'This request is no longer waiting.';
const ID3 = 'c'.repeat(32);
const ID0 = '0'.repeat(32);

const componentsCSS = readFileSync('src/styles/components.css', 'utf8');

const at = (s: number) => new Date(Date.now() - s * 1000).toISOString();

// A: destroys data, so approving it needs demo/data typed.
const severe = summary({ created: at(300) });
// B: a reversible patch, newer than A.
const plain = summary({
  id: ID2,
  rule: 'hold-writes',
  verb: 'patch',
  resource: 'deployments',
  name: 'web',
  summary: 'REVERSIBLE, 1 object',
  class: 'REVERSIBLE',
  data_destroyed: 0,
  created: at(60),
});
const plainImpact = impact({ class: 'REVERSIBLE', dataDestroyed: 0, undo: 'objects', effects: [{ kind: 'destroys', object: 'apps/Deployment/demo/web' }] });

const posts = (calls: Call[]) => calls.filter((c) => c.method === 'POST').map((c) => c.url);

// server stands in for the admin API: a mutable pending list, the detail
// of anything in it, and POSTs that succeed.
function server(initial: ApprovalSummary[]) {
  const state = { list: initial, all: [...initial] };
  const calls = mockFetch({
    'GET /api/approvals?status=pending': () => ({ body: state.list }),
    'GET /api/approvals/': (c) => {
      const s = state.all.find((x) => c.url.endsWith(`/${x.id}`));
      if (!s) return { status: 404, body: { error: 'not found' } };
      return { body: detail(s, s.id === ID2 ? plainImpact : impact()) };
    },
    'POST /api/approvals/': { body: {} },
  });
  return {
    calls,
    set(list: ApprovalSummary[]) {
      state.list = list;
      for (const s of list) if (!state.all.some((x) => x.id === s.id)) state.all.push(s);
    },
  };
}

// gated is a server whose list, details and POSTs can each be held back
// by the test, to land a reload in the middle of a decision.
function gated(initial: ApprovalSummary[]) {
  const state = { list: initial, all: [...initial] };
  let postGate: Promise<void> | null = null;
  let listGate: Promise<void> | null = null;
  const hold = () => {
    let release!: () => void;
    const p = new Promise<void>((r) => (release = r));
    return { p, release };
  };
  const calls = mockFetch({
    'GET /api/approvals?status=pending': async () => {
      // The list as it was when asked, even if it is answered later.
      const snapshot = state.list;
      if (listGate) await listGate;
      return { body: snapshot };
    },
    'GET /api/approvals/': (c) => {
      const s = state.all.find((x) => c.url.endsWith(`/${x.id}`))!;
      return { body: detail(s, s.id === ID2 ? plainImpact : impact()) };
    },
    'POST /api/approvals/': async () => {
      if (postGate) await postGate;
      return { body: {} };
    },
  });
  return {
    calls,
    set(list: ApprovalSummary[]) {
      state.list = list;
      for (const s of list) if (!state.all.some((x) => x.id === s.id)) state.all.push(s);
    },
    holdPosts() {
      const h = hold();
      postGate = h.p;
      return h.release;
    },
    holdLists() {
      const h = hold();
      listGate = h.p;
      return () => {
        listGate = null;
        h.release();
      };
    },
  };
}

const list = () => screen.getByRole('listbox', { name: /waiting for you/i });
const options = () => within(list()).getAllByRole('option');
const panel = () => screen.getByRole('article');
const heading = () => within(panel()).getByRole('heading', { level: 2 });

async function stream(ids: string[]) {
  await act(async () => emit('approvals', { count: ids.length, ids }));
}

describe('Waiting', () => {
  it('the list is oldest first even if the server sends newest first', async () => {
    setMedia(WIDE, true);
    // Newest first; two share a created time, and the id breaks the tie.
    const rows = [
      summary({ id: ID3, name: 'newest', created: at(10) }),
      summary({ id: ID2, name: 'tie-b', created: at(60) }),
      summary({ id: ID0, name: 'tie-a', created: at(60) }),
      summary({ id: ID1, name: 'oldest', created: at(300) }),
    ];
    server(rows);
    renderWithMotion(<Waiting me="bob" />);
    await waitFor(() => expect(options()).toHaveLength(4));
    const names = options().map((o) => within(o).getByText(/^Delete the volume claim /).textContent);
    expect(names).toEqual([
      'Delete the volume claim oldest',
      'Delete the volume claim tie-a',
      'Delete the volume claim tie-b',
      'Delete the volume claim newest',
    ]);
    // The oldest is the one chosen first: it is closest to expiring.
    expect(options()[0].getAttribute('aria-selected')).toBe('true');
  });

  it('expired approvals are never listed', async () => {
    setMedia(WIDE, true);
    const expired = summary({ id: ID3, name: 'stale', status: 'expired', created: at(900) });
    // A server that answers the status filter wrongly: the view asks for
    // pending only and still refuses to list anything else.
    const calls = mockFetch({
      'GET /api/approvals': { body: [expired, severe, plain] },
      'GET /api/approvals/': (c) => ({ body: detail(c.url.endsWith(ID2) ? plain : severe, impact()) }),
    });
    renderWithMotion(<Waiting me="bob" />);
    await waitFor(() => expect(options()).toHaveLength(2));
    expect(screen.queryByText(/stale/)).toBeNull();
    const listCalls = calls.filter((c) => c.url.startsWith('/api/approvals?'));
    expect(listCalls.length).toBeGreaterThan(0);
    for (const c of listCalls) expect(c.url).toBe('/api/approvals?status=pending');
  });

  it('stream events reload the list', async () => {
    setMedia(WIDE, true);
    const srv = server([severe]);
    renderWithMotion(<Waiting me="bob" />);
    await waitFor(() => expect(options()).toHaveLength(1));
    srv.set([severe, plain]);
    await stream([ID1, ID2]);
    await waitFor(() => expect(options()).toHaveLength(2));
    srv.set([plain]);
    await stream([ID2]);
    await waitFor(() => expect(screen.queryByText('Delete the volume claim data', { selector: '.waiting-sentence' })).toBeNull());
  });

  it('a stream row during load is not lost', async () => {
    setMedia(WIDE, true);
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let n = 0;
    mockFetch({
      'GET /api/approvals?status=pending': async () => {
        n++;
        // The first answer is slow and older than the stream event that
        // arrives while it is in flight.
        if (n === 1) {
          await gate;
          return { body: [severe] };
        }
        return { body: [severe, plain] };
      },
      'GET /api/approvals/': (c) => ({ body: detail(c.url.endsWith(ID2) ? plain : severe, impact()) }),
    });
    renderWithMotion(<Waiting me="bob" />);
    await stream([ID1, ID2]);
    await waitFor(() => expect(n).toBe(2));
    await act(async () => release());
    await waitFor(() => expect(options()).toHaveLength(2));
    await new Promise((r) => setTimeout(r, 30));
    expect(options()).toHaveLength(2);
  });

  it('wide screens show the list and the chosen request', async () => {
    setMedia(WIDE, true);
    server([plain, severe]);
    renderWithMotion(<Waiting me="bob" />);
    await waitFor(() => expect(options()).toHaveLength(2));
    const [a, b] = options();
    expect(within(a).getByText('Delete the volume claim data')).toBeTruthy();
    expect(within(a).getByText(/alice · /)).toBeTruthy();
    // The dot says its tone in words too, never colour alone.
    expect(within(a).getByText(/cannot be undone/i)).toBeTruthy();
    expect(within(b).getByText('Change the deployment web')).toBeTruthy();
    expect(heading().textContent).toBe('coding-agent wants to delete the volume claim demo/data');
    // No position line: that belongs to the one-at-a-time layout.
    expect(screen.queryByText(/of 2 waiting for you/)).toBeNull();

    await userEvent.click(b);
    expect(b.getAttribute('aria-selected')).toBe('true');
    expect(heading().textContent).toBe('coding-agent wants to change the deployment demo/web');
    // Each detail is fetched once, for the request being looked at.
    await within(panel()).findByText('Snapshot kept');
  });

  it('narrow screens show one at a time with its position', async () => {
    setMedia(WIDE, false);
    server([plain, severe]);
    renderWithMotion(<Waiting me="bob" />);
    expect(await screen.findByText('1 of 2 waiting for you')).toBeTruthy();
    expect(screen.queryByRole('listbox')).toBeNull();
    expect(screen.getAllByRole('article')).toHaveLength(1);
    expect(heading().textContent).toBe('coding-agent wants to delete the volume claim demo/data');
  });

  it('j and k move the selection when the list has focus', async () => {
    setMedia(WIDE, true);
    server([severe, plain, summary({ id: ID3, name: 'third', created: at(10) })]);
    renderWithMotion(<Waiting me="bob" />);
    await waitFor(() => expect(options()).toHaveLength(3));
    list().focus();
    await userEvent.keyboard('j');
    expect(options()[1].getAttribute('aria-selected')).toBe('true');
    expect(list().getAttribute('aria-activedescendant')).toBe(options()[1].id);
    expect(heading().textContent).toContain('demo/web');
    await userEvent.keyboard('j');
    expect(heading().textContent).toContain('demo/third');
    await userEvent.keyboard('k');
    expect(options()[1].getAttribute('aria-selected')).toBe('true');
    expect(heading().textContent).toContain('demo/web');
    // Focus stayed on the list the whole time.
    expect(document.activeElement).toBe(list());
  });

  it('after a decision the next request is chosen and focused', async () => {
    setMedia(WIDE, true);
    const srv = server([severe, plain]);
    renderWithMotion(<Waiting me="bob" />);
    await waitFor(() => expect(options()).toHaveLength(2));
    await within(panel()).findByText('None');
    await userEvent.click(within(panel()).getByRole('button', { name: /^deny$/i }));
    await waitFor(() => expect(heading().textContent).toContain('demo/web'));
    expect(posts(srv.calls)).toEqual([`/api/approvals/${ID1}/deny`]);
    await waitFor(() => expect(document.activeElement).toBe(heading()));
    await waitFor(() => expect(options()).toHaveLength(1));
    expect(options()[0].getAttribute('aria-selected')).toBe('true');
    expect(screen.getByText('Denied. The agent was refused.')).toBeTruthy();
  });

  it('after a decision on a narrow screen the next one is shown and focused', async () => {
    setMedia(WIDE, false);
    server([severe, plain]);
    renderWithMotion(<Waiting me="bob" />);
    expect(await screen.findByText('1 of 2 waiting for you')).toBeTruthy();
    await userEvent.click(within(panel()).getByRole('button', { name: /^deny$/i }));
    expect(await screen.findByText('1 of 1 waiting for you')).toBeTruthy();
    expect(heading().textContent).toContain('demo/web');
    await waitFor(() => expect(document.activeElement).toBe(heading()));
  });

  it('a new request is announced once', async () => {
    setMedia(WIDE, true);
    const srv = server([severe]);
    renderWithMotion(<Waiting me="bob" />);
    await waitFor(() => expect(options()).toHaveLength(1));
    // What was already waiting on arrival is not news.
    expect(announce).not.toHaveBeenCalled();
    srv.set([severe, plain]);
    await stream([ID1, ID2]);
    await waitFor(() => expect(options()).toHaveLength(2));
    await stream([ID1, ID2]);
    await new Promise((r) => setTimeout(r, 30));
    expect(announce).toHaveBeenCalledTimes(1);
    expect(announce).toHaveBeenCalledWith('New request waiting: Change the deployment web');
  });

  const newer = summary({ id: ID3, name: 'newer', created: at(5) });

  for (const width of ['wide', 'narrow'] as const) {
    it(`a request that arrives while a decision is in flight is kept (${width})`, async () => {
      setMedia(WIDE, width === 'wide');
      const srv = gated([severe]);
      renderWithMotion(<Waiting me="bob" />);
      await screen.findByRole('article');
      await within(panel()).findByText('None');
      const release = srv.holdPosts();
      await userEvent.click(within(panel()).getByRole('button', { name: /^deny$/i }));
      // While the deny is in flight, a new request comes in.
      srv.set([severe, newer]);
      await stream([ID1, ID3]);
      if (width === 'wide') await waitFor(() => expect(options()).toHaveLength(2));
      else expect(await screen.findByText('1 of 2 waiting for you')).toBeTruthy();
      srv.set([newer]);
      await act(async () => release());
      await waitFor(() => expect(heading().textContent).toContain('demo/newer'));
      expect(screen.queryByText('Nothing is waiting for you.')).toBeNull();
      if (width === 'wide') expect(options()).toHaveLength(1);
      else expect(screen.getByText('1 of 1 waiting for you')).toBeTruthy();
      expect(posts(srv.calls)).toEqual([`/api/approvals/${ID1}/deny`]);
    });
  }

  it('a list fetched before a decision landed does not bring the request back', async () => {
    setMedia(WIDE, true);
    const srv = gated([severe, plain]);
    renderWithMotion(<Waiting me="bob" />);
    await waitFor(() => expect(options()).toHaveLength(2));
    await within(panel()).findByText('None');
    const releasePost = srv.holdPosts();
    await userEvent.click(within(panel()).getByRole('button', { name: /^deny$/i }));
    // A reload is asked for before the deny resolves; it still lists A.
    const releaseList = srv.holdLists();
    await stream([ID1, ID2]);
    await act(async () => releasePost());
    await waitFor(() => expect(options()).toHaveLength(1));
    await act(async () => releaseList());
    await new Promise((r) => setTimeout(r, 30));
    expect(options()).toHaveLength(1);
    expect(heading().textContent).toContain('demo/web');
  });

  it('several requests arriving together are announced as a count', async () => {
    setMedia(WIDE, true);
    const srv = server([severe]);
    renderWithMotion(<Waiting me="bob" />);
    await waitFor(() => expect(options()).toHaveLength(1));
    srv.set([severe, plain, newer]);
    await stream([ID1, ID2, ID3]);
    await waitFor(() => expect(options()).toHaveLength(3));
    expect(announce).toHaveBeenCalledTimes(1);
    expect(announce).toHaveBeenCalledWith('2 new requests waiting');
  });

  it('a narrow screen keeps the request it shows when an older one arrives', async () => {
    setMedia(WIDE, false);
    const srv = server([plain]);
    renderWithMotion(<Waiting me="bob" />);
    expect(await screen.findByText('1 of 1 waiting for you')).toBeTruthy();
    expect(heading().textContent).toContain('demo/web');
    srv.set([severe, plain]);
    await stream([ID1, ID2]);
    expect(await screen.findByText('2 of 2 waiting for you')).toBeTruthy();
    expect(heading().textContent).toContain('demo/web');
  });

  it('a detail for a different request is an error with a retry', async () => {
    setMedia(WIDE, true);
    let wrong = true;
    mockFetch({
      'GET /api/approvals?status=pending': { body: [severe] },
      [`GET /api/approvals/${ID1}`]: () => ({ body: wrong ? detail(plain, plainImpact) : detail(severe, impact()) }),
    });
    renderWithMotion(<Waiting me="bob" />);
    expect(await within(await screen.findByRole('article')).findByText(/different request/)).toBeTruthy();
    wrong = false;
    await userEvent.click(within(panel()).getByRole('button', { name: 'Retry' }));
    await within(panel()).findByText('None');
    expect(within(panel()).queryByText(/different request/)).toBeNull();
  });

  it('the empty state says when the last decision was made', async () => {
    setMedia(WIDE, true);
    server([severe]);
    renderWithMotion(<Waiting me="bob" />);
    await waitFor(() => expect(options()).toHaveLength(1));
    await within(panel()).findByText('None');
    await userEvent.click(within(panel()).getByRole('button', { name: /^deny$/i }));
    expect(await screen.findByText('Nothing is waiting for you.')).toBeTruthy();
    expect(screen.getByText(/^Last decision at \d\d:\d\d\./)).toBeTruthy();
  });

  it('nothing waiting shows the empty state', async () => {
    server([]);
    renderWithMotion(<Waiting me="bob" />);
    expect(await screen.findByText('Nothing is waiting for you.')).toBeTruthy();
    expect(screen.queryByRole('article')).toBeNull();
    // No decision yet this session: no time to report.
    expect(screen.queryByText(/last decision/i)).toBeNull();
  });

  // B asks for the very same object as A, so its typed target is the same
  // demo/data: if anything typed for A carried over, it would complete B.
  const twin = summary({ id: ID2, created: at(60) });

  it('the request being typed for vanishing never retargets the confirm (wide)', async () => {
    setMedia(WIDE, true);
    const srv = server([severe, twin]);
    renderWithMotion(<Waiting me="bob" />);
    await waitFor(() => expect(options()).toHaveLength(2));
    await within(panel()).findByText('None');
    await userEvent.type(within(panel()).getByLabelText(/to approve, type/i), 'demo/dat');

    srv.set([twin]);
    await stream([ID2]);
    await waitFor(() => expect(options()).toHaveLength(1));

    // The panel still shows A, now gone, with nothing to press.
    expect(await within(panel()).findByText(GONE)).toBeTruthy();
    expect(heading().textContent).toContain('demo/data');
    expect(within(panel()).queryByRole('button', { name: /^approve$/i })).toBeNull();
    expect(within(panel()).queryByRole('button', { name: /^deny$/i })).toBeNull();
    expect(within(panel()).queryByRole('textbox')).toBeNull();
    // B is listed but not chosen: choosing it is the approver's call.
    expect(options()[0].getAttribute('aria-selected')).toBe('false');
    await userEvent.keyboard('a{Control>}{Enter}{/Control}');
    await new Promise((r) => setTimeout(r, 30));
    expect(posts(srv.calls)).toEqual([]);

    // Choosing B opens it fresh: nothing typed.
    await userEvent.click(options()[0]);
    const typed = within(panel()).getByLabelText(/to approve, type/i) as HTMLInputElement;
    expect(typed.value).toBe('');
  });

  it('the request being typed for vanishing never retargets the confirm (narrow)', async () => {
    setMedia(WIDE, false);
    const srv = server([severe, twin]);
    renderWithMotion(<Waiting me="bob" />);
    expect(await screen.findByText('1 of 2 waiting for you')).toBeTruthy();
    await within(panel()).findByText('None');
    const typedA = within(panel()).getByLabelText(/to approve, type/i) as HTMLInputElement;
    await userEvent.type(typedA, 'demo/dat');

    srv.set([twin]);
    await stream([ID2]);
    expect(await screen.findByText('1 of 1 waiting for you')).toBeTruthy();
    const typedB = within(panel()).getByLabelText(/to approve, type/i) as HTMLInputElement;
    expect(typedB).not.toBe(typedA);
    expect(typedB.value).toBe('');
    // The last keystroke A was waiting for, and the chord: nothing goes.
    typedB.focus();
    await userEvent.keyboard('a{Control>}{Enter}{/Control}');
    await new Promise((r) => setTimeout(r, 30));
    expect(posts(srv.calls)).toEqual([]);
  });

  it('long names never overflow at 360', async () => {
    const long = 'x'.repeat(253);
    const s = summary({ name: long, namespace: 'n'.repeat(63) });
    setMedia(WIDE, true);
    server([s]);
    const view = renderWithMotion(<Waiting me="bob" />);
    await waitFor(() => expect(options()).toHaveLength(1));
    expect(within(options()[0]).getByText(`Delete the volume claim ${long}`).classList.contains('waiting-wrap')).toBe(true);
    view.unmount();

    setMedia(WIDE, false);
    renderWithMotion(<Waiting me="bob" />);
    await screen.findByText('1 of 1 waiting for you');
    expect(heading().classList.contains('decision-q')).toBe(true);
    // Both classes break a name wherever they must.
    expect(componentsCSS).toMatch(/\.waiting-wrap\s*\{[^}]*overflow-wrap:\s*anywhere/);
    expect(componentsCSS).toMatch(/\.decision-q\s*\{[^}]*overflow-wrap:\s*anywhere/);
  });

  // Ported from the old Queue: the whole flow on one screen, with the
  // csrf header on every POST and the empty state at the end.
  it('a typed approve and a plain deny each post with the csrf header, then the empty state', async () => {
    setMedia(WIDE, true);
    const srv = server([severe, plain]);
    setCSRF('tok');
    renderWithMotion(<Waiting me="bob" />);
    await waitFor(() => expect(options()).toHaveLength(2));
    await within(panel()).findByText('None');
    // Destroying data: Approve waits for the whole target, typed.
    const field = within(panel()).getByLabelText(/to approve, type/i);
    const approve = within(panel()).getByRole('button', { name: /^approve$/i }) as HTMLButtonElement;
    await userEvent.type(field, 'demo/dat');
    expect(approve.disabled).toBe(true);
    await userEvent.type(field, 'a');
    expect(approve.disabled).toBe(false);
    await userEvent.click(approve);
    await waitFor(() => expect(heading().textContent).toContain('demo/web'));
    // A reversible change: no typing, and Deny sends at once.
    expect(within(panel()).queryByRole('textbox')).toBeNull();
    await within(panel()).findByText('Snapshot kept');
    await userEvent.click(within(panel()).getByRole('button', { name: /^deny$/i }));
    expect(await screen.findByText('Nothing is waiting for you.')).toBeTruthy();
    expect(posts(srv.calls)).toEqual([`/api/approvals/${ID1}/approve`, `/api/approvals/${ID2}/deny`]);
    expect(srv.calls.filter((c) => c.method === 'POST').every((c) => c.headers['x-blastgate-csrf'] === 'tok')).toBe(true);
  });

  it('a decision made elsewhere removes the request with a note', async () => {
    setMedia(WIDE, true);
    const calls = mockFetch({
      'GET /api/approvals?status=pending': { body: [plain] },
      [`GET /api/approvals/${ID2}`]: { body: detail(plain, plainImpact) },
      'POST /api/approvals/': { status: 409, body: { error: 'not pending' } },
    });
    renderWithMotion(<Waiting me="bob" />);
    await within(await screen.findByRole('article')).findByText('Snapshot kept');
    await userEvent.click(within(panel()).getByRole('button', { name: /^deny$/i }));
    expect(await screen.findByText('That request was already decided or has expired.')).toBeTruthy();
    await waitFor(() => expect(screen.queryByRole('option')).toBeNull());
    expect(posts(calls)).toEqual([`/api/approvals/${ID2}/deny`]);
  });
});
