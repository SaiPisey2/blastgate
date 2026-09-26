import { afterEach, describe, expect, it } from 'vitest';
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Feed from './Feed';
import { emit, setStreamStatus } from '../api';
import { mockFetch, type Call } from '../test/fetch';
import { feedRow } from '../test/fixtures';
import type { FeedRow } from '../api';

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

  it('a read recorded before reads had a class still shows as READ, and nothing else does', async () => {
    // Rows written by an older build: an allowed read's result row had an
    // empty class. Only that exact combination is shown as READ; any other
    // empty class stays UNMEASURED in the danger tone (P2-R14).
    const legacyRead = feedRow({ id: 30, request_id: 'q30', kind: 'result', rule: 'read', decision: 'allow', class: '', measured: false, verb: 'list', name: 'legacy-read' });
    const heldBlank = feedRow({ id: 31, request_id: 'q31', kind: 'result', rule: 'read', decision: 'hold', class: '', measured: false, name: 'not-a-read' });
    const decisionBlank = feedRow({ id: 32, request_id: 'q32', kind: 'decision', rule: 'read', decision: 'allow', class: '', measured: false, name: 'decision-blank' });
    mockFetch({ 'GET /api/feed': { body: [decisionBlank, heldBlank, legacyRead] } });
    render(<Feed />);
    const row = (await screen.findByText('legacy-read')).closest('tr')!;
    expect(row.className).toContain('muted');
    expect(within(row).getByText('READ').className).toContain('badge-read');
    for (const name of ['not-a-read', 'decision-blank']) {
      const other = screen.getByText(name).closest('tr')!;
      expect(other.className).not.toContain('muted');
      expect(within(other).getByText('UNMEASURED').className).toContain('badge-danger');
    }
  });

  it('an unmeasured row says so next to its class', async () => {
    const exec = feedRow({ id: 40, request_id: 'q40', kind: 'decision', verb: 'create', resource: 'pods', subresource: 'exec', class: 'TERMINAL', measured: false, decision: 'hold', name: 'db-0' });
    mockFetch({ 'GET /api/feed': { body: [exec] } });
    render(<Feed />);
    const row = (await screen.findByText('db-0')).closest('tr')!;
    expect(within(row).getByText('TERMINAL · UNMEASURED').className).toContain('badge-danger');
  });

  it('shows one row per request: a decision and then its result on the stream', async () => {
    mockFetch({ 'GET /api/feed': { body: [feedRow({ id: 5, kind: 'result', name: 'before-it' })] } });
    render(<Feed />);
    await screen.findByText('before-it');
    const decision = feedRow({ id: 60, request_id: 'q1', kind: 'decision', verb: 'create', resource: 'pods', subresource: 'exec', name: 'db-0', class: 'TERMINAL', measured: false, decision: 'hold', rule: 'exec-with-sql', status: 0, outcome: '' });
    act(() => emit('audit', decision));
    let row = (await screen.findByText('db-0')).closest('tr')!;
    // Written when the decision is made; the request has not ended yet.
    expect(within(row).getByText('in flight')).toBeTruthy();
    // Another request lands while the exec is still open.
    act(() => emit('audit', feedRow({ id: 61, kind: 'result', name: 'mid' })));
    act(() => emit('audit', { ...decision, id: 63, kind: 'result', status: 403, outcome: 'held' }));
    await waitFor(() => expect(screen.queryByText('in flight')).toBeNull());
    expect(screen.getAllByText('db-0')).toHaveLength(1);
    row = screen.getByText('db-0').closest('tr')!;
    expect(within(row).getByText('403')).toBeTruthy();
    expect(within(row).getByText('hold')).toBeTruthy();
    // A reconnecting stream can send the decision again: it changes nothing.
    act(() => emit('audit', decision));
    expect(screen.getAllByText('db-0')).toHaveLength(1);
    expect(within(screen.getByText('db-0').closest('tr')!).getByText('403')).toBeTruthy();
    // A newer request goes above it; the exec keeps its place.
    // Requests are placed by their first row: the exec was decided (60)
    // before "mid" (61), though its result (63) came after.
    act(() => emit('audit', feedRow({ id: 64, kind: 'result', name: 'newer' })));
    const names = screen.getAllByRole('row').slice(1).map((r) => r.querySelector('.name')!.textContent);
    expect(names).toEqual(['newer', 'mid', 'db-0', 'before-it']);
  });

  it('the result wins whichever row arrives first', async () => {
    mockFetch({ 'GET /api/feed': { body: [] } });
    render(<Feed />);
    await screen.findByText(/no requests/i);
    act(() => emit('audit', feedRow({ id: 71, request_id: 'q2', kind: 'result', status: 201, outcome: 'ok', name: 'cm' })));
    act(() => emit('audit', feedRow({ id: 70, request_id: 'q2', kind: 'decision', status: 0, outcome: '', name: 'cm' })));
    expect(await screen.findByText('201')).toBeTruthy();
    expect(screen.getAllByText('cm')).toHaveLength(1);
    expect(screen.queryByText('in flight')).toBeNull();
  });

  it('merges a request whose rows fall on two pages, and pages by raw rows', async () => {
    // Page 1 is 50 raw rows but only 26 requests: 24 decision/result
    // pairs, one read, and the result of a request whose decision is on
    // page 2. "More" follows the raw rows, and the cursor is the lowest
    // raw id seen (the low pair's decision, 140), not a shown row's id.
    const page1: FeedRow[] = [];
    const pair = (dec: number, res: number, name: string) => {
      const base = feedRow({ id: dec, request_id: `p-${name}`, kind: 'decision', status: 0, name });
      page1.push({ ...base, id: res, kind: 'result', status: 200 }, base);
    };
    for (let i = 0; i < 23; i++) pair(300 + 2 * i, 301 + 2 * i, `pair-${i}`);
    pair(140, 145, 'pair-low');
    page1.push(feedRow({ id: 160, kind: 'result', name: 'a-read', class: 'READ' }));
    page1.push(feedRow({ id: 150, request_id: 'split', kind: 'result', status: 200, outcome: 'ok', name: 'split-req' }));
    page1.sort((a, b) => b.id - a.id);
    const page2 = [feedRow({ id: 100, request_id: 'split', kind: 'decision', status: 0, outcome: '', name: 'split-req' }), feedRow({ id: 99, kind: 'result', name: 'oldest' })];
    const calls = mockFetch({ 'GET /api/feed': (c) => ({ body: params(c).get('before') ? page2 : page1 }) });
    render(<Feed />);
    await screen.findByText('split-req');
    expect(screen.getAllByRole('row').slice(1)).toHaveLength(26);
    await userEvent.click(screen.getByRole('button', { name: /load older/i }));
    expect(await screen.findByText('oldest')).toBeTruthy();
    expect(params(calls[calls.length - 1]).get('before')).toBe('140');
    expect(screen.getAllByText('split-req')).toHaveLength(1);
    const split = screen.getByText('split-req').closest('tr')!;
    expect(within(split).getByText('200')).toBeTruthy();
    expect(screen.queryByText('in flight')).toBeNull();
    // Placed by its first row (id 100): below the low pair (140), above 99.
    const names = screen.getAllByRole('row').slice(1).map((r) => r.querySelector('.name')!.textContent);
    expect(names.slice(-4)).toEqual(['a-read', 'pair-low', 'split-req', 'oldest']);
    // Page 2 was short: nothing older to offer.
    expect(screen.queryByRole('button', { name: /load older/i })).toBeNull();
  });

  it('the live indicator follows the stream', async () => {
    mockFetch({ 'GET /api/feed': { body: [] } });
    render(<Feed />);
    act(() => setStreamStatus('live'));
    expect(screen.getByRole('status').textContent).toBe('Live');
    act(() => setStreamStatus('reconnecting'));
    expect(screen.getByRole('status').textContent).toBe('Reconnecting');
    act(() => setStreamStatus('limited'));
    expect(screen.getByRole('status').textContent).toBe('Too many open tabs');
    act(() => setStreamStatus('offline'));
    expect(screen.getByRole('status').textContent).toBe('Offline');
  });
});
