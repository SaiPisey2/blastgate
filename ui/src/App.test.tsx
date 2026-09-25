import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import App from './App';
import { mockFetch } from './test/fetch';

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
});
