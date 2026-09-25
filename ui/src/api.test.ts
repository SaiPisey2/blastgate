import { afterEach, describe, expect, it } from 'vitest';
import { post, get, setCSRF, onSignedOut } from './api';
import { mockFetch } from './test/fetch';

afterEach(() => setCSRF(''));

describe('api', () => {
  it('api adds the CSRF header on POST only', async () => {
    const calls = mockFetch({
      'GET /api/feed': { body: [] },
      'POST /api/approvals/': { body: {} },
    });
    setCSRF('csrf-123');
    await get('/api/feed');
    await post(`/api/approvals/${'a'.repeat(32)}/approve`);
    expect(calls).toHaveLength(2);
    expect(calls[0].headers['x-blastgate-csrf']).toBeUndefined();
    expect(calls[1].headers['x-blastgate-csrf']).toBe('csrf-123');
  });

  it('never sends credentials to another origin', async () => {
    const calls = mockFetch({ 'GET /api/me': { body: { name: 'bob', csrf: 'x' } } });
    await get('/api/me');
    expect(calls[0].url).toBe('/api/me');
  });

  it('a 401 signs you out and forgets the CSRF value', async () => {
    const calls = mockFetch({
      'GET /api/feed': { status: 401, body: { error: 'unauthorized' } },
      'POST /api/logout': { body: {} },
    });
    setCSRF('csrf-123');
    let signedOut = 0;
    const off = onSignedOut(() => signedOut++);
    await expect(get('/api/feed')).rejects.toThrow();
    off();
    expect(signedOut).toBe(1);
    expect(window.location.hash).toBe('#/login');
    await post('/api/logout').catch(() => {});
    expect(calls[1].headers['x-blastgate-csrf']).toBeUndefined();
  });
});
