import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
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
