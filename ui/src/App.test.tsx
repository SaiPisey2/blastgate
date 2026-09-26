import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
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
