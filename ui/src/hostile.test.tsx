import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import Feed from './views/Feed';
import Queue from './views/Queue';
import { mockFetch } from './test/fetch';
import { detail, feedRow, impact, summary } from './test/fixtures';

afterEach(cleanup);

// Agents choose object names and command lines, so anything the API
// returns is attacker-controlled text. It must reach the page as text
// nodes: if any of it were parsed as HTML, this payload would create an
// <img> whose onerror runs script inside the approver's session.
const EVIL = '<img src=x onerror=alert(1)>';

describe('hostile text', () => {
  it('renders hostile names as text', async () => {
    const s = summary({ name: EVIL, namespace: EVIL, rule: EVIL, human: EVIL, agent: EVIL, summary: EVIL });
    mockFetch({
      'GET /api/feed': { body: [feedRow({ name: EVIL, namespace: EVIL, rule: EVIL, human: EVIL, agent: EVIL, resource: EVIL, verb: EVIL })] },
      'GET /api/approvals?status=pending': { body: [s] },
      [`GET /api/approvals/${s.id}`]: {
        body: detail(s, impact({ undo: EVIL, class: EVIL, effects: [{ kind: 'destroys-data', object: EVIL, explanation: EVIL }] })),
      },
    });

    const feed = render(<Feed />);
    const cell = await screen.findAllByText(EVIL, { exact: false });
    expect(cell.length).toBeGreaterThan(0);
    expect(feed.container.querySelector('img')).toBeNull();
    expect(feed.container.innerHTML).toContain('&lt;img');
    feed.unmount();

    const queue = render(<Queue />);
    const card = (await screen.findAllByText(EVIL, { exact: false }))[0].closest('article')!;
    // Wait for the detail (its class and undo text are hostile too).
    await waitFor(() => expect(within(card).getAllByText(EVIL).length).toBeGreaterThanOrEqual(7));
    expect(queue.container.querySelector('img')).toBeNull();
    expect(queue.container.querySelector('[onerror]')).toBeNull();
    expect(queue.container.innerHTML).toContain('&lt;img');
    // Typed confirm uses the namespace as the phrase: still literal text.
    expect(within(card).getAllByText(EVIL, { exact: false }).length).toBeGreaterThan(0);
  });
});
