import { afterEach, beforeEach, describe, expect, it } from 'vitest';
// @ts-expect-error -- this package has no @types/node; Vitest runs on Node.
import { readFileSync } from 'node:fs';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderWithMotion } from './test/motion';
import App from './App';
import { mockFetch } from './test/fetch';
import { emit } from './api';
import { act } from '@testing-library/react';
import { detail, feedRow, ID1, impact, summary } from './test/fixtures';

beforeEach(() => {
  window.location.hash = '#/feed';
});
afterEach(cleanup);

describe('App', () => {
  it('401 sends you to login', async () => {
    mockFetch({
      'GET /api/me': { body: { name: 'bob', csrf: 'c' } },
      'GET /api/approvals': { body: [] },
      'GET /api/feed': { status: 401, body: { error: 'unauthorized' } },
    });
    render(<App />);
    expect(await screen.findByLabelText(/login token/i)).toBeTruthy();
    expect(window.location.hash).toBe('#/login');
  });

  it('shows the login screen when there is no session', async () => {
    mockFetch({ 'GET /api/me': { status: 401, body: { error: 'unauthorized' } } });
    render(<App />);
    expect(await screen.findByLabelText(/login token/i)).toBeTruthy();
  });

  it('a stream count beats a slower initial fetch', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const calls = mockFetch({
      'GET /api/me': { body: { name: 'bob', csrf: 'c' } },
      'GET /api/feed': { body: [] },
      'GET /api/approvals': async () => {
        await gate;
        return { body: [] };
      },
    });
    render(<App />);
    await screen.findByText('bob');
    await waitFor(() => expect(calls.some((c) => c.url.startsWith('/api/approvals'))).toBe(true));
    act(() => emit('approvals', { count: 2, ids: ['a'.repeat(32), 'b'.repeat(32)] }));
    expect(screen.getByRole('link', { name: 'Waiting, 2 requests' })).toBeTruthy();
    await act(async () => release());
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.getByRole('link', { name: 'Waiting, 2 requests' })).toBeTruthy();
  });

  it('each new screen has a route, and held feed rows link to their approval', async () => {
    mockFetch({
      'GET /api/me': { body: { name: 'bob', csrf: 'c' } },
      'GET /api/approvals?status=pending': { body: [] },
      'GET /api/feed': { body: [feedRow({ decision: 'hold', approval_id: ID1, name: 'held-one' }), feedRow({ decision: 'hold', approval_id: '../x', name: 'crafted' })] },
      [`GET /api/approvals/${ID1}`]: { body: detail(summary(), impact()) },
      'GET /api/sessions': { body: [] },
      'GET /api/policy': { body: { source: 'built-in', text: 'rules: []' } },
      'GET /api/bypass': { body: [] },
    });
    render(<App />);
    const held = (await screen.findByText('held-one')).closest('.activity-row')!;
    const link = held.querySelector('a[href^="#/approvals/"]')!;
    expect(link.getAttribute('href')).toBe(`#/approvals/${ID1}`);
    // An approval id that is not one never becomes a link.
    expect(screen.getByText('crafted').closest('.activity-row')!.querySelector('a')).toBeNull();

    await act(async () => {
      window.location.hash = link.getAttribute('href')!;
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    });
    expect(await screen.findByRole('article')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Waiting' }).getAttribute('aria-current')).toBe('page');

    for (const [hash, heading] of [
      ['#/sessions', 'Agents'],
      ['#/policy', 'Policy'],
      ['#/bypass', 'Changes outside blastgate'],
    ]) {
      await act(async () => {
        window.location.hash = hash;
        window.dispatchEvent(new HashChangeEvent('hashchange'));
      });
      expect(await screen.findByRole('heading', { level: 1, name: heading })).toBeTruthy();
    }
    expect(screen.queryByText(/not built yet/i)).toBeNull();
  });
});

// M8: the self-approval guard depends on App handing /api/me's name down
// to both Waiting and Details. A view test passes `me` by hand, so only
// an App-level test catches that wiring being dropped.
describe('App self-approval wiring', () => {
  const REASON = "You can't approve a request made on your behalf";
  const mine = summary({ human: 'alice', class: 'REVERSIBLE', data_destroyed: 0, verb: 'patch', resource: 'deployments', name: 'web' });

  function routes() {
    mockFetch({
      'GET /api/me': { body: { name: 'alice', csrf: 'c' } },
      'GET /api/approvals?status=pending': { body: [mine] },
      [`GET /api/approvals/${ID1}`]: { body: detail(mine, impact({ class: 'REVERSIBLE', dataDestroyed: 0, undo: 'objects' })) },
    });
  }

  for (const [where, hash] of [
    ['Waiting', '#/waiting'],
    ['Details', `#/approvals/${ID1}`],
  ] as const) {
    it(`a request made on the approver's behalf cannot be approved on ${where}`, async () => {
      window.location.hash = hash;
      routes();
      render(<App />);
      const card = await screen.findByRole('article');
      expect(await within(card).findByText(REASON)).toBeTruthy();
      const approve = within(card).getByRole('button', { name: /^approve$/i }) as HTMLButtonElement;
      await waitFor(() => expect(approve.disabled).toBe(true));
    });
  }
});

// The v0.4.0 server rules, as the console shows them. App-level, because
// each one depends on wiring a view test passes by hand: the cluster from
// /api/me, the count endpoint, sign-in's return path, where Esc goes back.
describe('App server rules', () => {
  const componentsCSS = readFileSync('src/styles/components.css', 'utf8');
  const rule = (selector: string) => {
    const at = componentsCSS.indexOf(`\n${selector} {`);
    if (at < 0) throw new Error(`no rule for ${selector}`);
    return componentsCSS.slice(at, componentsCSS.indexOf('}', at));
  };
  const CLUSTER = 'kind-blastgate-fixture-with-a-rather-long-name';
  const plain = summary({ class: 'REVERSIBLE', data_destroyed: 0, verb: 'patch', resource: 'deployments', name: 'web', summary: 'REVERSIBLE, 1 object' });
  const plainImpact = impact({ class: 'REVERSIBLE', dataDestroyed: 0, undo: 'objects', effects: [{ kind: 'changed', object: 'apps/Deployment/demo/web' }] });

  it('cluster shows in the header and under the question', async () => {
    for (const hash of ['#/waiting', `#/approvals/${ID1}`]) {
      window.location.hash = hash;
      mockFetch({
        'GET /api/me': { body: { name: 'bob', csrf: 'c', cluster: CLUSTER } },
        'GET /api/approvals/count': { body: { count: 1 } },
        'GET /api/approvals?status=pending': { body: [plain] },
        [`GET /api/approvals/${ID1}`]: { body: detail(plain, plainImpact) },
      });
      const { unmount } = renderWithMotion(<App />);
      const header = await screen.findByRole('banner');
      const name = header.querySelector('.shell-cluster')!;
      expect(name.textContent).toBe(CLUSTER);
      expect(name.getAttribute('title')).toBe(CLUSTER);
      expect(name.classList.contains('mono')).toBe(true);
      // Right after the brand.
      expect(header.querySelector('.shell-brand')!.nextElementSibling).toBe(name);
      // Directly under the question, the name in mono.
      const card = await screen.findByRole('article');
      const q = within(card).getByRole('heading', { level: 2 });
      const line = q.nextElementSibling!;
      expect(line.textContent).toBe(`On cluster ${CLUSTER}`);
      expect(line.querySelector('.mono')!.textContent).toBe(CLUSTER);
      unmount();
    }
    // Cut short at 24ch with an ellipsis; the full name is in its title.
    const css = rule('.shell-cluster');
    expect(css).toMatch(/max-width:\s*24ch/);
    expect(css).toMatch(/text-overflow:\s*ellipsis/);
    expect(css).toMatch(/white-space:\s*nowrap/);
    expect(css).toMatch(/overflow:\s*hidden/);
    expect(css).toMatch(/color:\s*var\(--text-muted\)/);
  });

  it('the badge starts from the true count', async () => {
    window.location.hash = '#/activity';
    // The list is capped; the count is not.
    const calls = mockFetch({
      'GET /api/me': { body: { name: 'bob', csrf: 'c', cluster: 'c1' } },
      'GET /api/feed': { body: [] },
      'GET /api/approvals/count': { body: { count: 742 } },
      'GET /api/approvals?status=pending': { body: [summary()] },
    });
    renderWithMotion(<App />);
    expect(await screen.findByRole('link', { name: 'Waiting, 742 requests' })).toBeTruthy();
    expect(calls.some((c) => c.url === '/api/approvals/count')).toBe(true);
    // The stream keeps it current from there.
    act(() => emit('approvals', { count: 743, ids: [] }));
    expect(screen.getByRole('link', { name: 'Waiting, 743 requests' })).toBeTruthy();
  });

  it('a reauth refusal offers sign in again and returns to the same page', async () => {
    const hash = `#/approvals/${ID1}`;
    window.location.hash = hash;
    let signedIn = true;
    const calls = mockFetch({
      'GET /api/me': () => (signedIn ? { body: { name: 'bob', csrf: 'c', cluster: 'c1' } } : { status: 401, body: { error: 'unauthorized' } }),
      'GET /api/approvals/count': { body: { count: 1 } },
      'GET /api/approvals?status=pending': { body: [plain] },
      [`GET /api/approvals/${ID1}`]: { body: detail(plain, plainImpact) },
      [`POST /api/approvals/${ID1}/approve`]: { status: 403, body: { error: 'sign in again to approve access grants' } },
      'POST /api/logout': () => {
        signedIn = false;
        return { body: {} };
      },
      'POST /api/login': () => {
        signedIn = true;
        // As the server answers a sign-in: no cluster in it.
        return { body: { name: 'bob', csrf: 'c2' } };
      },
    });
    renderWithMotion(<App />);
    const card = await screen.findByRole('article');
    await userEvent.click(within(card).getByRole('button', { name: /^approve$/i }));
    const confirm = within(card).getByRole('button', { name: /confirm approval/i }) as HTMLButtonElement;
    await waitFor(() => expect(confirm.disabled).toBe(false));
    await userEvent.click(confirm);
    expect(await within(card).findByText('Sign in again to approve access grants')).toBeTruthy();
    expect(within(card).queryByText('sign in again to approve access grants')).toBeNull();
    await userEvent.click(within(card).getByRole('button', { name: 'Sign in again' }));
    expect(calls.some((c) => c.method === 'POST' && c.url === '/api/logout')).toBe(true);
    const field = (await screen.findByLabelText(/login token/i)) as HTMLInputElement;
    expect(window.location.hash).toBe('#/login');
    await userEvent.type(field, 'bga_again{Enter}');
    await waitFor(() => expect(window.location.hash).toBe(hash));
    expect(await screen.findByRole('article')).toBeTruthy();
    // The cluster is read again after the sign-in.
    await waitFor(() => expect(screen.getByRole('banner').querySelector('.shell-cluster')?.textContent).toBe('c1'));
  });

  it('esc from details returns to activity when that is where you came from', async () => {
    mockFetch({
      'GET /api/me': { body: { name: 'bob', csrf: 'c', cluster: 'c1' } },
      'GET /api/approvals/count': { body: { count: 1 } },
      'GET /api/approvals?status=pending': { body: [plain] },
      'GET /api/feed': { body: [] },
      [`GET /api/approvals/${ID1}`]: { body: detail(plain, plainImpact) },
    });
    const go = async (h: string) =>
      act(async () => {
        window.location.hash = h;
        window.dispatchEvent(new HashChangeEvent('hashchange'));
      });
    const escFromDetails = async () => {
      const card = await screen.findByRole('article');
      within(card).getByRole('heading', { level: 2 }).focus();
      await userEvent.keyboard('{Escape}');
    };

    // From Activity: back to Activity.
    window.location.hash = '#/activity';
    const first = renderWithMotion(<App />);
    await screen.findByRole('heading', { level: 1, name: 'Activity' });
    await go(`#/approvals/${ID1}`);
    await escFromDetails();
    await waitFor(() => expect(window.location.hash).toBe('#/activity'));

    // From Waiting: back to Waiting.
    await go('#/waiting');
    await go(`#/approvals/${ID1}`);
    await escFromDetails();
    await waitFor(() => expect(window.location.hash).toBe('#/waiting'));
    first.unmount();

    // A direct load: back to Waiting.
    window.location.hash = `#/approvals/${ID1}`;
    renderWithMotion(<App />);
    await escFromDetails();
    await waitFor(() => expect(window.location.hash).toBe('#/waiting'));
  });
});
