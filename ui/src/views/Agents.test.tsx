import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Agents from './Agents';
import { setCSRF } from '../api';
import { ARM_MS } from '../lib/friction';
import { mockFetch } from '../test/fetch';
import { session, SID1, SID2 } from '../test/fixtures';

const EVIL = '<img src=x onerror=alert(1)>';

afterEach(() => {
  cleanup();
  setCSRF('');
  vi.useRealTimers();
});

describe('Agents', () => {
  it('stop asks for confirmation, arms after a delay (boundary-checked), and sends the csrf header', async () => {
    let stopped = false;
    const calls = mockFetch({
      'GET /api/sessions': () => ({
        body: [
          session({ expires: new Date(Date.now() + 11 * 3_600_000).toISOString(), state: stopped ? 'revoked' : 'active' }),
          session({ id: SID2, human: 'bob', agent: 'review-agent', state: 'expired' }),
        ],
      }),
      [`POST /api/sessions/${SID1}/revoke`]: () => {
        stopped = true;
        return { body: {} };
      },
    });
    setCSRF('tok');
    render(<Agents />);

    const row = (await screen.findByText('coding-agent')).closest('tr')!;
    expect(within(row).getByText(/Active · 11h left/)).toBeTruthy();
    // Only a live agent can be stopped.
    const other = screen.getByText('review-agent').closest('tr')!;
    expect(within(other).queryByRole('button', { name: /^stop$/i })).toBeNull();
    expect(within(other).getByText('Expired')).toBeTruthy();

    // fireEvent, not userEvent, while the clock is fake: Testing Library's
    // async wrapper waits on a real setTimeout that only fake timers know
    // how to advance (matches DecisionPanel.test.tsx's own arm check).
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    fireEvent.click(within(row).getByRole('button', { name: /^stop$/i }));
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
    expect(within(row).getByText('Stop coding-agent for alice?')).toBeTruthy();
    const confirm = within(row).getByRole('button', { name: /^stop$/i }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    act(() => vi.advanceTimersByTime(ARM_MS - 1));
    expect(confirm.disabled).toBe(true);
    // A double-click on Stop lands its second click here, and is ignored
    // while it is not yet armed.
    fireEvent.click(confirm);
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
    act(() => vi.advanceTimersByTime(1));
    expect(confirm.disabled).toBe(false);
    vi.useRealTimers();

    // Cancel backs out without stopping anything.
    await userEvent.click(within(row).getByRole('button', { name: /cancel/i }));
    expect(calls.some((c) => c.method === 'POST')).toBe(false);

    await userEvent.click(within(row).getByRole('button', { name: /^stop$/i }));
    const confirm2 = within(row).getByRole('button', { name: /^stop$/i }) as HTMLButtonElement;
    await waitFor(() => expect(confirm2.disabled).toBe(false));
    await userEvent.click(confirm2);

    await waitFor(() => expect(within(screen.getByText('coding-agent').closest('tr')!).getByText('Stopped')).toBeTruthy());
    const posts = calls.filter((c) => c.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0].url).toBe(`/api/sessions/${SID1}/revoke`);
    expect(posts[0].headers['x-blastgate-csrf']).toBe('tok');
    expect(within(screen.getByText('coding-agent').closest('tr')!).queryByRole('button', { name: /^stop$/i })).toBeNull();
  });

  it('a failed stop says so and keeps the row live', async () => {
    mockFetch({
      'GET /api/sessions': { body: [session({ expires: new Date(Date.now() + 3 * 3_600_000).toISOString() })] },
      'POST /api/sessions/': { status: 500, body: { error: 'store unavailable' } },
    });
    render(<Agents />);
    const row = (await screen.findByText('coding-agent')).closest('tr')!;
    await userEvent.click(within(row).getByRole('button', { name: /^stop$/i }));
    const confirm = within(row).getByRole('button', { name: /^stop$/i }) as HTMLButtonElement;
    await waitFor(() => expect(confirm.disabled).toBe(false));
    await userEvent.click(confirm);
    expect(await screen.findByText(/store unavailable/)).toBeTruthy();
    expect(within(row).getByText(/Active/)).toBeTruthy();
  });

  it('status reads as time left', async () => {
    mockFetch({
      'GET /api/sessions': {
        body: [
          session({ id: SID1, agent: 'a1', expires: new Date(Date.now() + 11 * 3_600_000).toISOString(), state: 'active' }),
          session({ id: SID2, agent: 'a2', human: 'bob', state: 'revoked' }),
          session({ id: '3'.repeat(16), agent: 'a3', human: 'carol', state: 'expired' }),
          // The server still calls this one active, but its own expires
          // has already passed: it reads Expired too, and gets no Stop.
          session({ id: '4'.repeat(16), agent: 'a4', human: 'dan', expires: new Date(Date.now() - 1_000).toISOString(), state: 'active' }),
        ],
      },
    });
    render(<Agents />);
    await screen.findByText('a1');
    expect(within(screen.getByText('a1').closest('tr')!).getByText(/Active · 11h left/)).toBeTruthy();
    expect(within(screen.getByText('a2').closest('tr')!).getByText('Stopped')).toBeTruthy();
    expect(within(screen.getByText('a3').closest('tr')!).getByText('Expired')).toBeTruthy();
    const row4 = screen.getByText('a4').closest('tr')!;
    expect(within(row4).getByText('Expired')).toBeTruthy();
    expect(within(row4).queryByRole('button', { name: /^stop$/i })).toBeNull();
  });

  it('shows an empty state', async () => {
    mockFetch({ 'GET /api/sessions': { body: [] } });
    render(<Agents />);
    expect(await screen.findByText('No agents have signed in.')).toBeTruthy();
  });

  it('shows hostile agent, human and error strings as text, never as markup', async () => {
    mockFetch({
      'GET /api/sessions': { body: [session({ agent: EVIL, human: EVIL, expires: new Date(Date.now() + 3_600_000).toISOString() })] },
      'POST /api/sessions/': { status: 500, body: { error: EVIL } },
    });
    const { container } = render(<Agents />);

    const cells = await screen.findAllByText(EVIL);
    expect(cells.length).toBe(2); // the Agent cell and the On behalf of cell
    expect(container.querySelector('img')).toBeNull();

    const row = cells[0].closest('tr')!;
    await userEvent.click(within(row).getByRole('button', { name: /^stop$/i }));
    // The confirm sentence itself embeds the same hostile strings twice.
    expect(within(row).getByText(`Stop ${EVIL} for ${EVIL}?`)).toBeTruthy();
    const confirm = within(row).getByRole('button', { name: /^stop$/i }) as HTMLButtonElement;
    await waitFor(() => expect(confirm.disabled).toBe(false));
    await userEvent.click(confirm);

    await waitFor(() => expect(within(row).getByText(EVIL, { selector: '.agents-row-error' })).toBeTruthy());
    expect(container.querySelector('img')).toBeNull();
  });
});
