import { afterEach, describe, expect, it } from 'vitest';
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Feed from './Feed';
import { emit, setStreamStatus } from '../api';
import { mockFetch, type Call } from '../test/fetch';
import { feedRow } from '../test/fixtures';

afterEach(cleanup);

const read = feedRow({ id: 2, verb: 'get', class: 'READ', name: 'web-config', resource: 'configmaps', rule: 'reads' });
const held = feedRow({ id: 1, verb: 'delete', class: 'TERMINAL', name: 'data', resource: 'persistentvolumeclaims', decision: 'hold', rule: 'hold-terminal', status: 0 });

function params(c: Call) {
  return new URL(c.url, 'http://x').searchParams;
}

describe('Feed', () => {
  it('feed renders rows and filters', async () => {
    const calls = mockFetch({
      'GET /api/feed': (c) => {
        const p = params(c);
        if (p.get('class') === 'TERMINAL') return { body: [held] };
        if (p.get('before') === '1') return { body: [feedRow({ id: 0, name: 'older-pod' })] };
        // A full page, so the UI offers "load older".
        const filler = Array.from({ length: 48 }, (_, i) => feedRow({ id: 1000 + i, name: `pod-${i}` }));
        return { body: [...filler, read, held] };
      },
    });
    render(<Feed />);

    const readRow = (await screen.findByText('web-config')).closest('tr')!;
    expect(readRow.className).toContain('muted');
    expect(within(readRow).getByText('READ')).toBeTruthy();
    const heldRow = screen.getByText('data').closest('tr')!;
    expect(heldRow.className).not.toContain('muted');
    expect(within(heldRow).getByText('hold')).toBeTruthy();
    expect(within(heldRow).getByText('hold-terminal')).toBeTruthy();

    // "load older" pages with before=<oldest id shown>.
    await userEvent.click(screen.getByRole('button', { name: /load older/i }));
    expect(await screen.findByText('older-pod')).toBeTruthy();
    expect(params(calls[calls.length - 1]).get('before')).toBe('1');

    // A class filter asks the server again and shows only what it returns.
    await userEvent.selectOptions(screen.getByLabelText('Class'), 'TERMINAL');
    await waitFor(() => expect(screen.queryByText('web-config')).toBeNull());
    expect(screen.getByText('data')).toBeTruthy();
    expect(params(calls[calls.length - 1]).get('class')).toBe('TERMINAL');

    // Text filters reach the query string too.
    await userEvent.type(screen.getByLabelText('Agent'), 'coding-agent');
    await waitFor(() => expect(params(calls[calls.length - 1]).get('agent')).toBe('coding-agent'));

    // A live row that matches the filters is prepended; one that does not is dropped.
    act(() => emit('audit', feedRow({ id: 50, class: 'TERMINAL', name: 'live-match' })));
    act(() => emit('audit', feedRow({ id: 51, class: 'READ', name: 'live-other' })));
    expect(await screen.findByText('live-match')).toBeTruthy();
    expect(screen.queryByText('live-other')).toBeNull();
    const rows = screen.getAllByRole('row').slice(1);
    expect(within(rows[0]).getByText('live-match')).toBeTruthy();
  });

  it('shows an empty state when nothing matches', async () => {
    mockFetch({ 'GET /api/feed': { body: [] } });
    render(<Feed />);
    expect(await screen.findByText(/no requests/i)).toBeTruthy();
  });

  it('keeps rows that stream in while a page is loading', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    mockFetch({
      'GET /api/feed': async () => {
        await gate;
        return { body: [feedRow({ id: 10, name: 'from-page' }), feedRow({ id: 9, name: 'older-page' })] };
      },
    });
    render(<Feed />);
    // Arrives before the page does; one of them is also in the page.
    act(() => emit('audit', feedRow({ id: 11, name: 'early-live' })));
    act(() => emit('audit', feedRow({ id: 10, name: 'from-page' })));
    await act(async () => release());
    expect(await screen.findByText('early-live')).toBeTruthy();
    const names = screen.getAllByRole('row').slice(1).map((r) => r.querySelector('.name')!.textContent);
    expect(names).toEqual(['early-live', 'from-page', 'older-page']);
  });

  it('the live indicator follows the stream', async () => {
    mockFetch({ 'GET /api/feed': { body: [] } });
    render(<Feed />);
    act(() => setStreamStatus('live'));
    expect(screen.getByRole('status').textContent).toBe('Live');
    act(() => setStreamStatus('reconnecting'));
    expect(screen.getByRole('status').textContent).toBe('Reconnecting');
    act(() => setStreamStatus('offline'));
    expect(screen.getByRole('status').textContent).toBe('Offline');
  });
});
