import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Activity, { REFILL_MS, resetOutsideNotice, SUMMARY_MS } from './Activity';
import { announce } from '../components/Shell';
import { emit, type FeedRow } from '../api';
import { mockFetch, type Call } from '../test/fetch';
import { bypassRow, feedRow, ID1 } from '../test/fixtures';

// announce speaks through the shell's one alert region, which this file
// does not render; the spy is how a test hears what would be said.
vi.mock('../components/Shell', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../components/Shell')>()),
  announce: vi.fn(),
}));

beforeEach(() => {
  resetOutsideNotice();
  vi.mocked(announce).mockClear();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

const EVIL = '<img src=x onerror=alert(1)>';

// ok is a request that ended normally: the fixture's default outcome
// ('ok') is not one the proxy writes, and outcomeOf reads it as
// Interrupted.
function ok(over: Partial<FeedRow> = {}): FeedRow {
  return feedRow({ kind: 'result', outcome: '', status: 200, ...over });
}

function params(c: Call) {
  return new URL(c.url, 'http://x').searchParams;
}

const log = () => screen.getByRole('log');
const rowEls = () => Array.from(log().querySelectorAll<HTMLElement>('.activity-row'));
const names = () => rowEls().map((r) => r.querySelector('.activity-target')!.textContent);
const rowOf = (text: string) => screen.getByText(text).closest<HTMLElement>('.activity-row')!;
const summaryText = () => document.querySelector('.activity-summary')!.textContent;
const feedCalls = (calls: Call[]) => calls.filter((c) => c.url.startsWith('/api/feed'));

describe('Activity', () => {
  it('renders rows, filters by agent and human, and loads older', async () => {
    const read = ok({ id: 2, verb: 'get', class: 'READ', name: 'web-config', resource: 'configmaps', rule: 'reads' });
    const held = feedRow({ id: 1, verb: 'delete', class: 'TERMINAL', name: 'data', resource: 'persistentvolumeclaims', decision: 'hold', rule: 'hold-terminal', status: 403, kind: 'result', outcome: 'held' });
    const calls = mockFetch({
      'GET /api/bypass': { body: [] },
      'GET /api/feed': (c) => {
        const p = params(c);
        if (p.get('human') === 'bob') return { body: [ok({ id: 7, human: 'bob', name: 'bobs-pod' })] };
        if (p.get('before') === '1') return { body: [ok({ id: 0, name: 'older-pod' })] };
        // A full page, so the view offers "Load older".
        const filler = Array.from({ length: 48 }, (_, i) => ok({ id: 1000 + i, name: `pod-${i}` }));
        return { body: [...filler, read, held] };
      },
    });
    render(<Activity />);

    const readRow = (await screen.findByText('web-config')).closest('.activity-row')!;
    // Reads are the bulk of traffic and never need attention.
    expect(readRow.className).toContain('activity-row-read');
    expect(within(readRow as HTMLElement).getByText('Allowed')).toBeTruthy();
    const heldRow = rowOf('data');
    expect(heldRow.className).not.toContain('activity-row-read');
    expect(within(heldRow).getByText('Waiting')).toBeTruthy();

    // "Load older" pages with before=<lowest raw id seen>.
    await userEvent.click(screen.getByRole('button', { name: 'Load older' }));
    expect(await screen.findByText('older-pod')).toBeTruthy();
    expect(params(calls[calls.length - 1]).get('before')).toBe('1');

    // Text filters live behind "More filters" and go to the server.
    const more = screen.getByRole('button', { name: 'More filters' });
    expect(more.getAttribute('aria-expanded')).toBe('false');
    await userEvent.click(more);
    expect(more.getAttribute('aria-expanded')).toBe('true');
    await userEvent.type(screen.getByLabelText('Human'), 'bob');
    await waitFor(() => expect(screen.queryByText('web-config')).toBeNull());
    expect(screen.getByText('bobs-pod')).toBeTruthy();
    expect(params(calls[calls.length - 1]).get('human')).toBe('bob');

    await userEvent.type(screen.getByLabelText('Agent'), 'coding-agent');
    await waitFor(() => expect(params(calls[calls.length - 1]).get('agent')).toBe('coding-agent'));

    // The stream is unfiltered: a live row that matches is shown, one
    // that does not is dropped.
    act(() => emit('audit', ok({ id: 50, human: 'bob', name: 'live-match' })));
    act(() => emit('audit', ok({ id: 51, human: 'alice', name: 'live-other' })));
    expect(await screen.findByText('live-match')).toBeTruthy();
    expect(screen.queryByText('live-other')).toBeNull();
    expect(names()[0]).toBe('live-match');
  });

  it('says so when there are no requests', async () => {
    mockFetch({ 'GET /api/bypass': { body: [] }, 'GET /api/feed': { body: [] } });
    render(<Activity />);
    expect(await screen.findByText('No requests yet.')).toBeTruthy();
  });

  it('keeps rows that stream in while a page is loading', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    mockFetch({
      'GET /api/bypass': { body: [] },
      'GET /api/feed': async () => {
        await gate;
        return { body: [ok({ id: 10, name: 'from-page' }), ok({ id: 9, name: 'older-page' })] };
      },
    });
    render(<Activity />);
    // Arrives before the page does; one of them is also in the page.
    act(() => emit('audit', ok({ id: 11, name: 'early-live' })));
    act(() => emit('audit', ok({ id: 10, name: 'from-page' })));
    await act(async () => release());
    expect(await screen.findByText('early-live')).toBeTruthy();
    expect(names()).toEqual(['early-live', 'from-page', 'older-page']);
  });

  it('a read recorded before reads had a class still shows as a read, and nothing else does', async () => {
    // Rows written by an older build: an allowed read's result row had an
    // empty class. Only that exact combination reads as READ (P2-R14).
    const legacyRead = feedRow({ id: 30, request_id: 'q30', kind: 'result', rule: 'read', decision: 'allow', class: '', measured: false, verb: 'list', outcome: '', name: 'legacy-read' });
    const heldBlank = feedRow({ id: 31, request_id: 'q31', kind: 'result', rule: 'read', decision: 'hold', class: '', measured: false, name: 'not-a-read' });
    const decisionBlank = feedRow({ id: 32, request_id: 'q32', kind: 'decision', rule: 'read', decision: 'allow', class: '', measured: false, name: 'decision-blank' });
    mockFetch({ 'GET /api/bypass': { body: [] }, 'GET /api/feed': { body: [decisionBlank, heldBlank, legacyRead] } });
    render(<Activity />);
    await screen.findByText('not-a-read');
    // A list has no name to point at; the row is found by its sentence.
    const row = screen.getByText('Read the list of pods').closest('.activity-row')!;
    expect(row.className).toContain('activity-row-read');
    for (const name of ['not-a-read', 'decision-blank']) expect(rowOf(name).className).not.toContain('activity-row-read');
  });

  it('shows one row per request: a decision and then its result on the stream', async () => {
    mockFetch({ 'GET /api/bypass': { body: [] }, 'GET /api/feed': { body: [ok({ id: 5, name: 'before-it' })] } });
    render(<Activity />);
    await screen.findByText('before-it');
    const decision = feedRow({ id: 60, request_id: 'q1', kind: 'decision', verb: 'create', resource: 'pods', subresource: 'exec', name: 'db-0', class: 'TERMINAL', measured: false, decision: 'hold', rule: 'exec-with-sql', status: 0, outcome: '' });
    act(() => emit('audit', decision));
    // Written when the decision is made; the request has not ended yet.
    expect(within(rowOf('db-0')).getByText('In flight')).toBeTruthy();
    // Another request lands while the exec is still open.
    act(() => emit('audit', ok({ id: 61, name: 'mid' })));
    act(() => emit('audit', { ...decision, id: 63, kind: 'result', status: 403, outcome: 'held' }));
    await waitFor(() => expect(screen.queryByText('In flight')).toBeNull());
    expect(screen.getAllByText('db-0')).toHaveLength(1);
    expect(within(rowOf('db-0')).getByText('Waiting')).toBeTruthy();
    // A resumed stream can send the decision again: it changes nothing.
    act(() => emit('audit', decision));
    expect(screen.getAllByText('db-0')).toHaveLength(1);
    expect(within(rowOf('db-0')).getByText('Waiting')).toBeTruthy();
    // Requests are placed by their first row: the exec was decided (60)
    // before "mid" (61), though its result (63) came after.
    act(() => emit('audit', ok({ id: 64, name: 'newer' })));
    expect(names()).toEqual(['newer', 'mid', 'db-0', 'before-it']);
  });

  it('the result wins whichever row arrives first', async () => {
    mockFetch({ 'GET /api/bypass': { body: [] }, 'GET /api/feed': { body: [] } });
    render(<Activity />);
    await screen.findByText('No requests yet.');
    act(() => emit('audit', feedRow({ id: 71, request_id: 'q2', kind: 'result', status: 201, outcome: '', name: 'cm' })));
    act(() => emit('audit', feedRow({ id: 70, request_id: 'q2', kind: 'decision', status: 0, outcome: '', name: 'cm' })));
    await screen.findByText('cm');
    expect(within(rowOf('cm')).getByText('Allowed')).toBeTruthy();
    expect(screen.getAllByText('cm')).toHaveLength(1);
    expect(screen.queryByText('In flight')).toBeNull();
  });

  it('a merged request shows the time of its first row', async () => {
    mockFetch({ 'GET /api/bypass': { body: [] }, 'GET /api/feed': { body: [] } });
    render(<Activity />);
    await screen.findByText('No requests yet.');
    // A long exec: decided at 10:15, ended at 10:45. It shows the
    // decision's time, whichever row came first.
    act(() => emit('audit', feedRow({ id: 81, request_id: 'q3', kind: 'result', at: '2026-09-26T10:45:00Z', status: 101, outcome: '', name: 'long' })));
    act(() => emit('audit', feedRow({ id: 80, request_id: 'q3', kind: 'decision', at: '2026-09-26T10:15:00Z', status: 0, name: 'long' })));
    act(() => emit('audit', feedRow({ id: 91, request_id: 'q4', kind: 'decision', at: '2026-09-26T11:00:00Z', status: 0, name: 'later' })));
    act(() => emit('audit', feedRow({ id: 92, request_id: 'q4', kind: 'result', at: '2026-09-26T11:30:00Z', status: 200, outcome: '', name: 'later' })));
    const timeOf = (name: string) => rowOf(name).querySelector('time')!.getAttribute('datetime');
    await waitFor(() => expect(screen.queryByText('In flight')).toBeNull());
    expect(timeOf('long')).toBe('2026-09-26T10:15:00Z');
    expect(timeOf('later')).toBe('2026-09-26T11:00:00Z');
  });

  it('merges a request whose rows fall on two pages, and pages by raw rows', async () => {
    // Page 1 is 50 raw rows but only 26 requests: 24 decision/result
    // pairs, one read, and the result of a request whose decision is on
    // page 2. "More" follows the raw rows, and the cursor is the lowest
    // raw id seen (the low pair's decision, 140), not a shown row's id.
    const page1: FeedRow[] = [];
    const pair = (dec: number, res: number, name: string) => {
      const base = feedRow({ id: dec, request_id: `p-${name}`, kind: 'decision', status: 0, outcome: '', name });
      page1.push({ ...base, id: res, kind: 'result', status: 200 }, base);
    };
    for (let i = 0; i < 23; i++) pair(300 + 2 * i, 301 + 2 * i, `pair-${i}`);
    pair(140, 145, 'pair-low');
    page1.push(ok({ id: 160, name: 'a-read', class: 'READ' }));
    page1.push(ok({ id: 150, request_id: 'split', name: 'split-req' }));
    page1.sort((a, b) => b.id - a.id);
    const page2 = [feedRow({ id: 100, request_id: 'split', kind: 'decision', status: 0, outcome: '', name: 'split-req' }), ok({ id: 99, name: 'oldest' })];
    const calls = mockFetch({ 'GET /api/bypass': { body: [] }, 'GET /api/feed': (c) => ({ body: params(c).get('before') ? page2 : page1 }) });
    render(<Activity />);
    await screen.findByText('split-req');
    expect(rowEls()).toHaveLength(26);
    await userEvent.click(screen.getByRole('button', { name: 'Load older' }));
    expect(await screen.findByText('oldest')).toBeTruthy();
    const feeds = feedCalls(calls);
    expect(params(feeds[feeds.length - 1]).get('before')).toBe('140');
    expect(screen.getAllByText('split-req')).toHaveLength(1);
    expect(within(rowOf('split-req')).getByText('Allowed')).toBeTruthy();
    expect(screen.queryByText('In flight')).toBeNull();
    // Placed by its first row (id 100): below the low pair (140), above 99.
    expect(names().slice(-4)).toEqual(['a-read', 'pair-low', 'split-req', 'oldest']);
    // Page 2 was short: nothing older to offer.
    expect(screen.queryByRole('button', { name: 'Load older' })).toBeNull();
  });

  it('a held row links to its approval only when the id is a real one', async () => {
    mockFetch({
      'GET /api/bypass': { body: [] },
      'GET /api/feed': { body: [feedRow({ id: 3, decision: 'hold', approval_id: ID1, name: 'held-one' }), feedRow({ id: 2, decision: 'hold', approval_id: '../x', name: 'crafted' }), ok({ id: 1, approval_id: ID1, name: 'allowed-one' })] },
    });
    render(<Activity />);
    const link = (await screen.findByText('held-one')).closest('a')!;
    expect(link.getAttribute('href')).toBe(`#/approvals/${ID1}`);
    // approval_id is API data; only a real id may reach the hash.
    expect(rowOf('crafted').querySelector('a')).toBeNull();
    expect(rowOf('allowed-one').querySelector('a')).toBeNull();
  });

  it('renders hostile names as text', async () => {
    mockFetch({
      'GET /api/bypass': { body: [] },
      'GET /api/feed': { body: [feedRow({ name: EVIL, namespace: EVIL, rule: EVIL, human: EVIL, agent: EVIL, resource: EVIL, verb: EVIL, decision: 'hold', approval_id: EVIL })] },
    });
    const { container } = render(<Activity />);
    await waitFor(() => expect(screen.getAllByText(EVIL, { exact: false }).length).toBeGreaterThanOrEqual(2));
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('[onerror]')).toBeNull();
    expect(container.querySelector('a')).toBeNull();
    expect(container.innerHTML).toContain('&lt;img');
  });

  it('each row reads as a sentence', async () => {
    mockFetch({
      'GET /api/bypass': { body: [] },
      'GET /api/feed': {
        body: [
          ok({ id: 4, verb: 'delete', resource: 'persistentvolumeclaims', name: 'data', human: 'alice', agent: 'coding-agent', at: '2026-09-26T10:15:00Z' }),
          feedRow({ id: 3, kind: 'result', decision: 'deny', status: 403, outcome: 'denied', verb: 'create', resource: 'clusterrolebindings', group: 'rbac.authorization.k8s.io', namespace: '', name: 'admin-me', human: 'bob' }),
          feedRow({ id: 2, kind: 'result', status: 503, outcome: 'upstream', name: 'broken' }),
          feedRow({ id: 1, kind: 'result', status: 101, outcome: 'aborted', subresource: 'exec', name: 'db-0' }),
        ],
      },
    });
    render(<Activity />);
    const row = (await screen.findByText('data')).closest<HTMLElement>('.activity-row')!;
    const text = row.textContent!;
    expect(text).toContain('Delete the volume claim data');
    expect(text).toContain('alice via coding-agent');
    // The target is an identifier: always mono text.
    expect(screen.getByText('data').className).toContain('mono');
    const time = row.querySelector('time')!;
    expect(time.getAttribute('datetime')).toBe('2026-09-26T10:15:00Z');
    expect(time.className).toContain('activity-when');
    // The outcome is a word with a tone, never a status code.
    expect(within(row).getByText('Allowed').closest('.activity-outcome')!.className).toContain('activity-outcome-neutral');
    expect(text).not.toContain('200');
    const denied = rowOf('admin-me');
    expect(denied.textContent).toContain('Grant access with the cluster role binding admin-me');
    expect(denied.textContent).toContain('bob via coding-agent');
    expect(within(denied).getByText('Denied').closest('.tag')!.className).toContain('tag-danger');
    expect(within(rowOf('broken')).getByText('Failed').closest('.tag')!.className).toContain('tag-danger');
    expect(rowOf('db-0').textContent).toContain('Run a command in db-0');
    expect(within(rowOf('db-0')).getByText('Interrupted').closest('.tag')!.className).toContain('tag-caution');
  });

  it('outcome chips filter the list', async () => {
    mockFetch({
      'GET /api/bypass': { body: [] },
      'GET /api/feed': {
        body: [
          ok({ id: 4, name: 'allowed-one' }),
          feedRow({ id: 3, kind: 'result', decision: 'hold', status: 403, outcome: 'held', name: 'waiting-one' }),
          feedRow({ id: 2, kind: 'result', decision: 'deny', status: 403, outcome: 'denied', name: 'denied-one' }),
          feedRow({ id: 1, kind: 'decision', decision: 'allow', status: 0, outcome: '', name: 'flight-one' }),
        ],
      },
    });
    render(<Activity />);
    await screen.findByText('allowed-one');
    const chip = (name: string) => screen.getByRole('button', { name });
    expect(chip('All').getAttribute('aria-pressed')).toBe('true');
    expect(names()).toEqual(['allowed-one', 'waiting-one', 'denied-one', 'flight-one']);

    await userEvent.click(chip('Waiting'));
    expect(chip('Waiting').getAttribute('aria-pressed')).toBe('true');
    expect(chip('All').getAttribute('aria-pressed')).toBe('false');
    expect(names()).toEqual(['waiting-one']);

    await userEvent.click(chip('Denied'));
    expect(names()).toEqual(['denied-one']);

    await userEvent.click(chip('Allowed'));
    expect(names()).toEqual(['allowed-one']);

    // A live row is filtered the same way.
    act(() => emit('audit', feedRow({ id: 9, kind: 'result', decision: 'deny', status: 403, outcome: 'denied', name: 'live-denied' })));
    act(() => emit('audit', ok({ id: 10, name: 'live-allowed' })));
    await screen.findByText('live-allowed');
    expect(screen.queryByText('live-denied')).toBeNull();

    // Back to All, everything is there, the live rows included.
    await userEvent.click(chip('All'));
    expect(names()).toHaveLength(6);
  });

  it('new rows wait behind a pill while you read', async () => {
    const page = Array.from({ length: 8 }, (_, i) => ok({ id: 100 - i, name: `row-${i}` }));
    mockFetch({ 'GET /api/bypass': { body: [] }, 'GET /api/feed': { body: page } });
    render(<Activity />);
    await screen.findByText('row-0');
    const fifth = rowEls()[4];
    act(() => fifth.focus());
    expect(document.activeElement).toBe(fifth);

    act(() => {
      for (let i = 0; i < 10; i++) emit('audit', ok({ id: 200 + i, name: `live-${i}` }));
    });
    // Nothing moved under the reader: the same node at the same index.
    expect(rowEls()[4]).toBe(fifth);
    expect(rowEls()).toHaveLength(8);
    expect(screen.queryByText('live-0')).toBeNull();
    const pill = screen.getByRole('button', { name: /10 new/ });
    expect(pill.textContent).toBe('↑ 10 new');

    // A row for a request already on screen updates it in place: its
    // place does not change, so it does not count as new.
    act(() => emit('audit', { ...page[4], kind: 'result' }));
    expect(screen.getByRole('button', { name: /10 new/ })).toBeTruthy();
    expect(rowEls()[4]).toBe(fifth);

    const list = log();
    list.scrollTop = 120;
    await userEvent.click(pill);
    expect(rowEls()).toHaveLength(18);
    expect(names().slice(0, 3)).toEqual(['live-9', 'live-8', 'live-7']);
    expect(screen.queryByRole('button', { name: /new/ })).toBeNull();
    expect(list.scrollTop).toBe(0);
    // The pill is gone; focus lands on the list it filled, not the page.
    expect(document.activeElement).toBe(list);
  });

  it('scrolling or the pointer over the list holds new rows too', async () => {
    mockFetch({ 'GET /api/bypass': { body: [] }, 'GET /api/feed': { body: [ok({ id: 1, name: 'first' })] } });
    render(<Activity />);
    await screen.findByText('first');
    const list = log();

    list.scrollTop = 40;
    fireEvent.scroll(list);
    act(() => emit('audit', ok({ id: 2, name: 'while-scrolled' })));
    expect(screen.queryByText('while-scrolled')).toBeNull();
    expect(screen.getByRole('button', { name: /1 new/ })).toBeTruthy();
    list.scrollTop = 0;
    fireEvent.scroll(list);

    fireEvent.pointerEnter(list);
    act(() => emit('audit', ok({ id: 3, name: 'while-pointing' })));
    expect(screen.queryByText('while-pointing')).toBeNull();
    expect(screen.getByRole('button', { name: /2 new/ })).toBeTruthy();
    fireEvent.pointerLeave(list);

    // Nobody is reading: the next row goes straight in, with the ones
    // that waited, and the pill goes away.
    act(() => emit('audit', ok({ id: 4, name: 'at-rest' })));
    expect(names()).toEqual(['at-rest', 'while-pointing', 'while-scrolled', 'first']);
    expect(screen.queryByRole('button', { name: /new/ })).toBeNull();
    // A row that goes straight in is tinted for a moment.
    expect(rowOf('at-rest').className).toContain('activity-row-fresh');
    expect(rowOf('first').className).not.toContain('activity-row-fresh');
  });

  it('pause holds new rows', async () => {
    mockFetch({ 'GET /api/bypass': { body: [] }, 'GET /api/feed': { body: [ok({ id: 1, name: 'first' })] } });
    render(<Activity />);
    await screen.findByText('first');
    const pause = screen.getByRole('button', { name: 'Pause' });
    expect(pause.getAttribute('aria-pressed')).toBe('false');
    await userEvent.click(pause);
    expect(pause.getAttribute('aria-pressed')).toBe('true');

    act(() => emit('audit', ok({ id: 2, name: 'held-back' })));
    act(() => emit('audit', ok({ id: 3, name: 'held-back-2' })));
    expect(screen.queryByText('held-back')).toBeNull();
    expect(screen.getByRole('button', { name: /2 new/ }).textContent).toBe('↑ 2 new');

    // Resuming asks for the live list again, so what waited comes in.
    await userEvent.click(pause);
    expect(pause.getAttribute('aria-pressed')).toBe('false');
    expect(names()).toEqual(['held-back-2', 'held-back', 'first']);
    expect(screen.queryByRole('button', { name: /new/ })).toBeNull();
  });

  it('the list is not a live region; one summary speaks for a burst', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mockFetch({ 'GET /api/bypass': { body: [] }, 'GET /api/feed': { body: [ok({ id: 1, name: 'first' })] } });
    render(<Activity />);
    await screen.findByText('first');
    expect(log().getAttribute('aria-live')).toBe('off');
    expect(summaryText()).toBe('');
    act(() => {
      for (let i = 0; i < 3; i++) emit('audit', ok({ id: 10 + i, name: `burst-${i}` }));
    });
    expect(screen.getByText('burst-2')).toBeTruthy();
    // Nothing is said at once; one summary covers the whole burst.
    act(() => vi.advanceTimersByTime(SUMMARY_MS - 500));
    expect(summaryText()).toBe('');
    act(() => vi.advanceTimersByTime(500));
    expect(summaryText()).toBe('3 new requests');

    // Held rows are summarised as waiting.
    fireEvent.pointerEnter(log());
    act(() => emit('audit', ok({ id: 20, name: 'held-a' })));
    act(() => emit('audit', ok({ id: 21, name: 'held-b' })));
    act(() => vi.advanceTimersByTime(SUMMARY_MS));
    expect(summaryText()).toBe('2 new requests waiting above the list');
  });

  it('load older and the chips never change the summary', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const full = Array.from({ length: 50 }, (_, i) => ok({ id: 500 - i, name: `p-${i}` }));
    mockFetch({
      'GET /api/bypass': { body: [] },
      'GET /api/feed': (c) => ({ body: params(c).get('before') ? Array.from({ length: 20 }, (_, i) => ok({ id: 100 - i, name: `old-${i}` })) : full }),
    });
    render(<Activity />);
    await screen.findByText('p-0');
    act(() => emit('audit', ok({ id: 900, name: 'live-one' })));
    act(() => vi.advanceTimersByTime(SUMMARY_MS));
    expect(summaryText()).toBe('1 new request');

    fireEvent.click(screen.getByRole('button', { name: 'Load older' }));
    expect(await screen.findByText('old-19')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Denied' }));
    fireEvent.click(screen.getByRole('button', { name: 'All' }));
    act(() => vi.advanceTimersByTime(SUMMARY_MS * 2));
    expect(summaryText()).toBe('1 new request');
  });

  it('the tint is forgotten once it has played, so a chip change does not replay it', async () => {
    mockFetch({ 'GET /api/bypass': { body: [] }, 'GET /api/feed': { body: [] } });
    render(<Activity />);
    await screen.findByText('No requests yet.');
    act(() => emit('audit', ok({ id: 1, name: 'arrived' })));
    expect(rowOf('arrived').className).toContain('activity-row-fresh');
    await waitFor(() => expect(rowOf('arrived').className).not.toContain('activity-row-fresh'));
    await userEvent.click(screen.getByRole('button', { name: 'Denied' }));
    await userEvent.click(screen.getByRole('button', { name: 'All' }));
    expect(rowOf('arrived').className).not.toContain('activity-row-fresh');
  });

  it('while reading, an older row of a request on screen waits with the rest', async () => {
    mockFetch({
      'GET /api/bypass': { body: [] },
      'GET /api/feed': { body: [ok({ id: 10, request_id: 'qa', name: 'a-req' }), ok({ id: 8, name: 'b-req' })] },
    });
    render(<Activity />);
    await screen.findByText('a-req');
    fireEvent.pointerEnter(log());
    // Its decision (id 5) places the request below b-req (8).
    act(() => emit('audit', feedRow({ id: 5, request_id: 'qa', kind: 'decision', status: 0, outcome: '', name: 'a-req' })));
    expect(names()).toEqual(['a-req', 'b-req']);
    fireEvent.pointerLeave(log());
    act(() => emit('audit', ok({ id: 30, name: 'c-req' })));
    expect(names()).toEqual(['c-req', 'b-req', 'a-req']);
  });

  it('the pill counts only what the chosen chip would show', async () => {
    mockFetch({ 'GET /api/bypass': { body: [] }, 'GET /api/feed': { body: [feedRow({ id: 1, kind: 'result', decision: 'deny', status: 403, outcome: 'denied', name: 'd-0' })] } });
    render(<Activity />);
    await screen.findByText('d-0');
    await userEvent.click(screen.getByRole('button', { name: 'Denied' }));
    fireEvent.pointerEnter(log());
    act(() => emit('audit', ok({ id: 2, name: 'allowed-live' })));
    act(() => emit('audit', feedRow({ id: 3, kind: 'result', decision: 'deny', status: 403, outcome: 'denied', name: 'denied-live' })));
    expect(screen.getByRole('button', { name: /new/ }).textContent).toBe('↑ 1 new');
  });

  it('while focus is in the list, a request on screen finishes in place', async () => {
    mockFetch({
      'GET /api/bypass': { body: [] },
      'GET /api/feed': { body: [ok({ id: 9, name: 'top' }), feedRow({ id: 5, request_id: 'qx', kind: 'decision', status: 0, outcome: '', name: 'running' })] },
    });
    render(<Activity />);
    await screen.findByText('running');
    expect(within(rowOf('running')).getByText('In flight')).toBeTruthy();
    const row = rowOf('running');
    act(() => row.focus());
    act(() => emit('audit', feedRow({ id: 12, request_id: 'qx', kind: 'result', status: 200, outcome: '', name: 'running' })));
    expect(within(rowOf('running')).getByText('Allowed')).toBeTruthy();
    expect(rowOf('running')).toBe(row);
    expect(screen.queryByRole('button', { name: /new/ })).toBeNull();
  });

  it('while reading, an update that would show a hidden row waits behind the pill', async () => {
    mockFetch({
      'GET /api/bypass': { body: [] },
      'GET /api/feed': {
        body: [feedRow({ id: 9, kind: 'result', decision: 'hold', status: 403, outcome: 'held', name: 'held-top' }), feedRow({ id: 5, request_id: 'qh', kind: 'decision', decision: 'hold', status: 0, outcome: '', name: 'soon-held' })],
      },
    });
    render(<Activity />);
    await screen.findByText('soon-held');
    await userEvent.click(screen.getByRole('button', { name: 'Waiting' }));
    expect(names()).toEqual(['held-top']);
    fireEvent.pointerEnter(log());
    act(() => emit('audit', feedRow({ id: 12, request_id: 'qh', kind: 'result', decision: 'hold', status: 403, outcome: 'held', name: 'soon-held' })));
    expect(names()).toEqual(['held-top']);
    expect(screen.getByRole('button', { name: /new/ }).textContent).toBe('↑ 1 new');
    await userEvent.click(screen.getByRole('button', { name: /new/ }));
    expect(names()).toEqual(['held-top', 'soon-held']);
  });

  it('when the cap trims rows that load older reached, it offers them again', async () => {
    const page = Array.from({ length: 1000 }, (_, i) => ok({ id: 5000 - i, name: `r-${i}` }));
    mockFetch({
      'GET /api/bypass': { body: [] },
      'GET /api/feed': (c) => ({ body: params(c).get('before') ? [ok({ id: 10, name: 'deep' })] : page }),
    });
    render(<Activity />);
    await screen.findByText('r-0');
    await userEvent.click(screen.getByRole('button', { name: 'Load older' }));
    await screen.findByText('deep');
    // A short page: nothing older to offer, for now.
    expect(screen.queryByRole('button', { name: 'Load older' })).toBeNull();
    act(() => emit('audit', ok({ id: 9000, name: 'newest' })));
    expect(screen.queryByText('deep')).toBeNull();
    expect(screen.getByRole('button', { name: 'Load older' })).toBeTruthy();
  });

  it('the banner appears only when there are outside changes', async () => {
    const calls = mockFetch({ 'GET /api/bypass': { body: [bypassRow(), bypassRow({ name: 'other' })] }, 'GET /api/feed': { body: [] } });
    const first = render(<Activity />);
    const banner = await screen.findByRole('region', { name: /changes were made without going through blastgate/ });
    expect(within(banner).getByText('2 changes were made without going through blastgate')).toBeTruthy();
    expect(within(banner).getByText('Someone used their own credentials. Review them.')).toBeTruthy();
    expect(within(banner).getByRole('link').getAttribute('href')).toBe('#/activity/outside');
    const bypass = calls.find((c) => c.url.startsWith('/api/bypass'))!;
    expect(params(bypass).get('since_hours')).toBe('24');
    expect(params(bypass).get('limit')).toBe('500');
    await waitFor(() => expect(announce).toHaveBeenCalledTimes(1));
    expect(vi.mocked(announce).mock.calls[0][0]).toBe('2 changes were made without going through blastgate');

    // Back on Activity later in the same session: the banner is still
    // there to read, but it is not said out loud again.
    first.unmount();
    render(<Activity />);
    await screen.findByRole('region', { name: /changes were made/ });
    await new Promise((r) => setTimeout(r, 20));
    expect(announce).toHaveBeenCalledTimes(1);
    cleanup();

    // One change reads in the singular.
    mockFetch({ 'GET /api/bypass': { body: [bypassRow()] }, 'GET /api/feed': { body: [] } });
    render(<Activity />);
    expect(await screen.findByText('1 change was made without going through blastgate')).toBeTruthy();
    cleanup();

    mockFetch({ 'GET /api/bypass': { body: [] }, 'GET /api/feed': { body: [] } });
    render(<Activity />);
    await screen.findByText('No requests yet.');
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByText(/without going through blastgate/)).toBeNull();
  });
});

describe('Activity, carried from review', () => {
  it('the same summary twice running is emptied and said again', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mockFetch({ 'GET /api/bypass': { body: [] }, 'GET /api/feed': { body: [] } });
    render(<Activity />);
    await screen.findByText('No requests yet.');
    act(() => emit('audit', ok({ id: 1, name: 'one' })));
    act(() => vi.advanceTimersByTime(SUMMARY_MS));
    expect(summaryText()).toBe('1 new request');
    act(() => emit('audit', ok({ id: 2, name: 'two' })));
    act(() => vi.advanceTimersByTime(SUMMARY_MS));
    // Emptied first, so the region changes and is spoken again.
    expect(summaryText()).toBe('');
    act(() => vi.advanceTimersByTime(REFILL_MS));
    expect(summaryText()).toBe('1 new request');
  });
});
