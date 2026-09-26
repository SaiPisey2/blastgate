import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Bypass from './Bypass';
import { mockFetch } from '../test/fetch';
import { bypassRow } from '../test/fixtures';

afterEach(cleanup);

describe('Bypass', () => {
  it('bypass renders rows', async () => {
    // Served oldest first on purpose: the view orders newest first itself.
    const calls = mockFetch({
      'GET /api/bypass': {
        body: [
          bypassRow({ at: '2026-09-26T08:00:00Z', name: 'old-job', resource: 'jobs', group: 'batch' }),
          bypassRow({ at: '2026-09-26T10:00:00Z', name: 'db-0', resource: 'pods', group: '', subresource: 'exec', user: 'kubernetes-admin', groups: ['system:masters'], dry_run: true }),
          bypassRow({ at: '2026-09-26T09:00:00Z' }),
        ],
      },
    });
    render(<Bypass />);

    expect(screen.getByText('These writes reached the cluster without going through blastgate.')).toBeTruthy();
    const table = (await screen.findByText('db-0')).closest('table')!;
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows.map((r) => r.querySelector('.target .name')!.textContent)).toEqual(['db-0', 'web', 'old-job']);

    const top = rows[0];
    expect(within(top).getByText('kubernetes-admin')).toBeTruthy();
    expect(within(top).getByText('system:masters')).toBeTruthy();
    expect(within(top).getByText('delete')).toBeTruthy();
    expect(within(top).getByText('pods')).toBeTruthy();
    expect(within(top).getByText('/exec')).toBeTruthy();
    expect(within(top).getByText('dry run')).toBeTruthy();
    expect(within(rows[1]).queryByText('dry run')).toBeNull();
    expect(within(rows[1]).getByText('apps/')).toBeTruthy();
    expect(within(rows[1]).getByText('system:serviceaccount:team-a:deployer')).toBeTruthy();
    expect(within(rows[1]).getByText('team-a/')).toBeTruthy();

    expect(calls[0].url).toMatch(/^\/api\/bypass\?/);
    expect(new URL(calls[0].url, 'http://x').searchParams.get('since_hours')).toBe('168');

    // The window is adjustable, and re-queries.
    await userEvent.selectOptions(screen.getByLabelText(/window/i), '720');
    await waitFor(() => expect(calls).toHaveLength(2));
    expect(new URL(calls[1].url, 'http://x').searchParams.get('since_hours')).toBe('720');
  });

  it('says what an empty list means', async () => {
    mockFetch({ 'GET /api/bypass': { body: [] } });
    render(<Bypass />);
    expect(await screen.findByText(/no writes bypassed blastgate/i)).toBeTruthy();
    expect(screen.getByText(/webhook is not configured/i)).toBeTruthy();
  });
});
