import { describe, expect, it } from 'vitest';
import { parseHash } from './router';

const ID = 'a'.repeat(32);

describe('parseHash', () => {
  it('maps every page to its route', () => {
    const cases: [string, ReturnType<typeof parseHash>][] = [
      ['', { name: 'waiting' }],
      ['#', { name: 'waiting' }],
      ['#/', { name: 'waiting' }],
      ['#/waiting', { name: 'waiting' }],
      ['#/activity', { name: 'activity' }],
      ['#/activity/outside', { name: 'outside' }],
      ['#/agents', { name: 'agents' }],
      ['#/policy', { name: 'policy' }],
      ['#/login', { name: 'login' }],
      [`#/approvals/${ID}`, { name: 'approval', id: ID }],
    ];
    for (const [hash, want] of cases) expect(parseHash(hash), hash).toEqual(want);
  });

  it('old hashes still land on the right page', () => {
    // Bookmarks, chat links and the webhook's own links were written
    // against the old names; they must keep opening the same screen.
    expect(parseHash('#/queue')).toEqual({ name: 'waiting' });
    expect(parseHash('#/feed')).toEqual({ name: 'activity' });
    expect(parseHash('#/bypass')).toEqual({ name: 'outside' });
    expect(parseHash('#/sessions')).toEqual({ name: 'agents' });
  });

  it('approval ids are validated', () => {
    for (const hash of [
      '#/approvals/../x',
      '#/approvals/..%2Fx',
      `#/approvals/${ID.toUpperCase()}`,
      `#/approvals/${ID}0`,
      `#/approvals/${ID.slice(1)}`,
      `#/approvals/${ID}/x`,
      '#/approvals',
      '#/approvals/',
    ]) {
      expect(parseHash(hash), hash).toEqual({ name: 'notfound' });
    }
  });

  it('anything else is not found', () => {
    for (const hash of ['#/nope', '#/waiting/x', '#/activity/inside', '#/activity/outside/x', '#/queue/x', '#/agents/1', '#/Waiting', '#/constructor', '#/__proto__']) {
      expect(parseHash(hash), hash).toEqual({ name: 'notfound' });
    }
  });
});
