import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Sessions from './Sessions';
import { setCSRF } from '../api';
import { mockFetch } from '../test/fetch';
import { session, SID1, SID2 } from '../test/fixtures';

afterEach(() => {
  cleanup();
  setCSRF('');
});

describe('Sessions', () => {
  it('sessions revoke asks for confirmation', async () => {
    let revoked = false;
    const calls = mockFetch({
      'GET /api/sessions': () => ({
        body: [session({ state: revoked ? 'revoked' : 'active' }), session({ id: SID2, human: 'bob', agent: 'review-agent', state: 'expired' })],
      }),
      [`POST /api/sessions/${SID1}/revoke`]: () => {
        revoked = true;
        return { body: {} };
      },
    });
    setCSRF('tok');
    render(<Sessions />);

    const row = (await screen.findByText('coding-agent')).closest('tr')!;
    expect(within(row).getByText('active')).toBeTruthy();
    // Only a live session can be revoked.
    const other = screen.getByText('review-agent').closest('tr')!;
    expect(within(other).queryByRole('button', { name: /revoke/i })).toBeNull();

    // The first click only asks.
    await userEvent.click(within(row).getByRole('button', { name: /^revoke$/i }));
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
    expect(within(row).getByText(/stops working at once/i)).toBeTruthy();
    const confirm = within(row).getByRole('button', { name: /confirm revoke/i }) as HTMLButtonElement;
    // A double-click on Revoke lands its second click here, and is ignored.
    await userEvent.click(confirm);
    expect(calls.some((c) => c.method === 'POST')).toBe(false);

    // Cancel backs out without revoking.
    await userEvent.click(within(row).getByRole('button', { name: /cancel/i }));
    expect(calls.some((c) => c.method === 'POST')).toBe(false);

    await userEvent.click(within(row).getByRole('button', { name: /^revoke$/i }));
    const confirm2 = within(row).getByRole('button', { name: /confirm revoke/i }) as HTMLButtonElement;
    await waitFor(() => expect(confirm2.disabled).toBe(false));
    await userEvent.click(confirm2);

    await waitFor(() => expect(within(screen.getByText('coding-agent').closest('tr')!).getByText('revoked')).toBeTruthy());
    const posts = calls.filter((c) => c.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0].url).toBe(`/api/sessions/${SID1}/revoke`);
    expect(posts[0].headers['x-blastgate-csrf']).toBe('tok');
    expect(within(screen.getByText('coding-agent').closest('tr')!).queryByRole('button', { name: /revoke/i })).toBeNull();
  });

  it('a failed revoke says so and keeps the row', async () => {
    mockFetch({
      'GET /api/sessions': { body: [session()] },
      'POST /api/sessions/': { status: 500, body: { error: 'store unavailable' } },
    });
    render(<Sessions />);
    const row = (await screen.findByText('coding-agent')).closest('tr')!;
    await userEvent.click(within(row).getByRole('button', { name: /^revoke$/i }));
    const confirm = within(row).getByRole('button', { name: /confirm revoke/i }) as HTMLButtonElement;
    await waitFor(() => expect(confirm.disabled).toBe(false));
    await userEvent.click(confirm);
    expect(await screen.findByText(/store unavailable/)).toBeTruthy();
    expect(within(row).getByText('active')).toBeTruthy();
  });

  it('shows an empty state', async () => {
    mockFetch({ 'GET /api/sessions': { body: [] } });
    render(<Sessions />);
    expect(await screen.findByText(/no agent sessions/i)).toBeTruthy();
  });
});
