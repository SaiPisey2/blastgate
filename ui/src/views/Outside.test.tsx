import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Outside from './Outside';
import { mockFetch } from '../test/fetch';
import { bypassRow } from '../test/fixtures';

afterEach(cleanup);

const EVIL = '<img src=x onerror=alert(1)>';

const rowEls = () => Array.from(document.querySelectorAll<HTMLElement>('.outside-row'));
const since = (url: string) => new URL(url, 'http://x').searchParams.get('since_hours');

// whole matches a sentence split across a text node and its mono name.
const whole = (text: string) => (_: string, el: Element | null) => !!el && el.parentElement?.classList.contains('outside-what') === true && el.textContent === text;

describe('Outside', () => {
  it('lists outside changes newest first, in plain words', async () => {
    // Served oldest first on purpose: the view orders newest first itself.
    const calls = mockFetch({
      'GET /api/bypass': {
        body: [
          bypassRow({ at: '2026-09-26T08:00:00Z', name: 'old-job', resource: 'jobs', group: 'batch' }),
          bypassRow({ at: '2026-09-26T10:00:00Z', verb: 'create', name: 'db-0', resource: 'pods', group: '', subresource: 'exec', user: 'kubernetes-admin', groups: ['system:masters'], dry_run: true }),
          bypassRow({ at: '2026-09-26T09:00:00Z' }),
        ],
      },
    });
    render(<Outside />);

    expect(screen.getByText('These writes reached the cluster without going through blastgate.')).toBeTruthy();
    await screen.findByText(whole('Run a command in db-0'));
    // The name inside the sentence is set in mono, as in Activity.
    expect(screen.getByText('db-0', { selector: '.outside-ident' }).className).toContain('mono');
    const rows = rowEls();
    expect(rows.map((r) => r.querySelector('.outside-target')!.textContent)).toEqual(['team-a/db-0', 'team-a/web', 'team-a/old-job']);

    const top = rows[0];
    expect(within(top).getByText('kubernetes-admin')).toBeTruthy();
    expect(within(top).getByText('system:masters').className).toContain('outside-groups');
    expect(within(top).getByText('Dry run')).toBeTruthy();
    expect(within(top).getByText('team-a/db-0').className).toContain('mono');
    expect(top.querySelector('time')!.getAttribute('datetime')).toBe('2026-09-26T10:00:00Z');

    expect(within(rows[1]).getByText(whole('Delete the deployment web'))).toBeTruthy();
    expect(within(rows[1]).queryByText('Dry run')).toBeNull();
    expect(within(rows[1]).getByText('system:serviceaccount:team-a:deployer')).toBeTruthy();
    expect(within(rows[1]).getByText('system:serviceaccounts, system:serviceaccounts:team-a')).toBeTruthy();

    expect(calls[0].url).toMatch(/^\/api\/bypass\?/);
    expect(new URL(calls[0].url, 'http://x').searchParams.get('limit')).toBe('500');
  });

  it('the range selector changes since_hours', async () => {
    const calls = mockFetch({ 'GET /api/bypass': { body: [bypassRow()] } });
    render(<Outside />);
    await screen.findByText(whole('Delete the deployment web'));
    // The banner on Activity counts the last 24 hours; its link lands on
    // the same count.
    expect(since(calls[0].url)).toBe('24');
    const range = screen.getByLabelText('Period');
    await userEvent.selectOptions(range, '168');
    await waitFor(() => expect(calls).toHaveLength(2));
    expect(since(calls[1].url)).toBe('168');
    await userEvent.selectOptions(range, '720');
    await waitFor(() => expect(calls).toHaveLength(3));
    expect(since(calls[2].url)).toBe('720');
  });

  it('says what an empty list means', async () => {
    mockFetch({ 'GET /api/bypass': { body: [] } });
    render(<Outside />);
    expect(await screen.findByText('No changes outside blastgate in this period.')).toBeTruthy();
    expect(screen.getByText(/webhook is not configured/i)).toBeTruthy();
  });

  it('renders hostile text as text', async () => {
    mockFetch({
      'GET /api/bypass': {
        body: [bypassRow({ user: EVIL, groups: [EVIL, EVIL], verb: EVIL, group: EVIL, resource: EVIL, subresource: EVIL, namespace: EVIL, name: EVIL })],
      },
    });
    const { container } = render(<Outside />);
    await waitFor(() => expect(screen.getAllByText(EVIL, { exact: false }).length).toBeGreaterThanOrEqual(3));
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('[onerror]')).toBeNull();
    expect(container.innerHTML).toContain('&lt;img');
  });
});

describe('Outside, Esc (final review M2)', () => {
  it('Esc goes back to Activity, but not from the period select', async () => {
    mockFetch({ 'GET /api/bypass': { body: [bypassRow()] } });
    window.location.hash = '#/outside';
    render(<Outside />);
    await waitFor(() => expect(rowEls().length).toBe(1));
    const select = screen.getByRole('combobox');
    select.focus();
    await userEvent.keyboard('{Escape}');
    expect(window.location.hash).toBe('#/outside');
    (document.activeElement as HTMLElement).blur();
    await userEvent.keyboard('{Escape}');
    expect(window.location.hash).toBe('#/activity');
  });
});
