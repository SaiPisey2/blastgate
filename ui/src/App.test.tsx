import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import App from './App';
import { mockFetch } from './test/fetch';
import { emit } from './api';
import { act } from '@testing-library/react';

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
    mockFetch({
      'GET /api/me': { body: { name: 'bob', csrf: 'c' } },
      'GET /api/feed': { body: [] },
      'GET /api/approvals': async () => {
        await gate;
        return { body: [] };
      },
    });
    render(<App />);
    await screen.findByText('bob');
    act(() => emit('approvals', { count: 2, ids: ['a'.repeat(32), 'b'.repeat(32)] }));
    expect(screen.getByLabelText('2 pending')).toBeTruthy();
    await act(async () => release());
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.getByLabelText('2 pending')).toBeTruthy();
  });
});
