import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Policy from './Policy';
import { setCSRF, type ReplayResult } from '../api';
import { mockFetch } from '../test/fetch';

afterEach(() => {
  cleanup();
  setCSRF('');
});

const LOADED = 'rules:\n  - name: safe\n    when: action.verb == "get"\n    decision: allow\n';
const PARSE_ERROR = 'rule "hold-terminal": ERROR: <input>:1:8: undeclared reference to \'impactt\'\n | impactt.class == "TERMINAL"\n | .......^';

const RESULT: ReplayResult = {
  evaluated: 412,
  changed: 2,
  skipped: 3,
  truncated: false,
  changes: [
    {
      at: '2026-09-26T09:30:00Z',
      request_id: 'r-1',
      verb: 'delete',
      resource: 'pods',
      namespace: 'team-a',
      name: 'web-7d9f8c-abcde',
      rule_before: 'safe-writes',
      rule_after: 'hold-deletes',
      decision_before: 'allow',
      decision_after: 'hold',
    },
    {
      at: '2026-09-26T09:40:00Z',
      request_id: 'r-2',
      verb: 'create',
      resource: 'pods/exec',
      namespace: 'team-a',
      name: 'db-0',
      rule_before: 'hold-exec',
      rule_after: 'deny-exec',
      decision_before: 'hold',
      decision_after: 'deny',
    },
  ],
};

describe('Policy', () => {
  it('policy replay shows changes and parse errors', async () => {
    let bad = false;
    const calls = mockFetch({
      'GET /api/policy': { body: { source: '/etc/blastgate/policy.yaml', text: LOADED } },
      'POST /api/policy/replay': () => (bad ? { status: 400, body: { error: PARSE_ERROR } } : { body: RESULT }),
    });
    setCSRF('tok');
    render(<Policy />);

    // The loaded policy, read-only, with where it came from.
    expect(await screen.findByText('/etc/blastgate/policy.yaml')).toBeTruthy();
    const loaded = screen.getByLabelText('Loaded policy');
    expect(loaded.textContent).toBe(LOADED);
    // There is nothing to apply from here.
    expect(screen.queryByRole('button', { name: /apply/i })).toBeNull();

    const candidate = screen.getByLabelText(/candidate policy/i) as HTMLTextAreaElement;
    await waitFor(() => expect(candidate.value).toBe(LOADED));
    await userEvent.clear(candidate);
    await userEvent.type(candidate, 'rules: [[]'); // [[ types a literal [
    const hours = screen.getByLabelText(/hours/i) as HTMLInputElement;
    await userEvent.clear(hours);
    await userEvent.type(hours, '48');
    await userEvent.click(screen.getByRole('button', { name: 'Replay over the last 48 hours' }));

    const post = await waitFor(() => {
      const p = calls.find((c) => c.method === 'POST');
      expect(p).toBeTruthy();
      return p!;
    });
    expect(post.url).toBe('/api/policy/replay');
    expect(JSON.parse(post.body!)).toEqual({ policy: 'rules: []', since_hours: 48 });
    expect(post.headers['x-blastgate-csrf']).toBe('tok');

    const result = await screen.findByRole('region', { name: 'Replay result' });
    expect(within(result).getByText('412')).toBeTruthy();
    expect(within(result).getByText('Evaluated')).toBeTruthy();
    expect(within(result).getByText('Changed')).toBeTruthy();
    const row = within(result).getByText('web-7d9f8c-abcde').closest('tr')!;
    expect(within(row).getByText('safe-writes')).toBeTruthy();
    expect(within(row).getByText('hold-deletes')).toBeTruthy();
    expect(within(row).getByText('allow')).toBeTruthy();
    expect(within(row).getByText('hold')).toBeTruthy();
    expect(within(result).getByText('db-0')).toBeTruthy();
    expect(within(result).queryByText(/only the first/i)).toBeNull();

    // A policy that does not load: the parser's message, verbatim, as text.
    bad = true;
    await userEvent.click(screen.getByRole('button', { name: 'Replay over the last 48 hours' }));
    const err = await screen.findByLabelText('Policy error');
    expect(err.tagName).toBe('PRE');
    expect(err.textContent).toBe(PARSE_ERROR);
    // The stale result from the earlier candidate is gone.
    expect(screen.queryByRole('region', { name: 'Replay result' })).toBeNull();
  });

  it('since_hours outside 1..720 is refused before sending', async () => {
    const calls = mockFetch({
      'GET /api/policy': { body: { source: 'built-in', text: LOADED } },
      'POST /api/policy/replay': { body: RESULT },
    });
    render(<Policy />);
    await screen.findByText('built-in');
    const hours = screen.getByLabelText(/hours/i) as HTMLInputElement;
    for (const v of ['0', '721', '2.5']) {
      await userEvent.clear(hours);
      await userEvent.type(hours, v);
      await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
      expect(await screen.findByText(/whole number of hours from 1 to 720/i)).toBeTruthy();
    }
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
    await userEvent.clear(hours);
    await userEvent.type(hours, '720');
    await userEvent.click(screen.getByRole('button', { name: 'Replay over the last 720 hours' }));
    await waitFor(() => expect(calls.filter((c) => c.method === 'POST')).toHaveLength(1));
    expect(JSON.parse(calls.find((c) => c.method === 'POST')!.body!).since_hours).toBe(720);
  });

  it('says when nothing would change', async () => {
    mockFetch({
      'GET /api/policy': { body: { source: 'built-in', text: LOADED } },
      'POST /api/policy/replay': { body: { evaluated: 10, changed: 0, skipped: 0, changes: [] } },
    });
    render(<Policy />);
    const candidate = (await screen.findByLabelText(/candidate policy/i)) as HTMLTextAreaElement;
    await waitFor(() => expect(candidate.value).toBe(LOADED));
    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    expect(await screen.findByText(/no request would have been decided differently/i)).toBeTruthy();
  });

  it('a truncated replay says it covered only the first decisions', async () => {
    mockFetch({
      'GET /api/policy': { body: { source: 'built-in', text: LOADED } },
      'POST /api/policy/replay': { body: { ...RESULT, evaluated: 100000, truncated: true } },
    });
    render(<Policy />);
    const candidate = (await screen.findByLabelText(/candidate policy/i)) as HTMLTextAreaElement;
    await waitFor(() => expect(candidate.value).toBe(LOADED));
    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    const result = await screen.findByRole('region', { name: 'Replay result' });
    expect(within(result).getByText('Only the first 100000 decisions in this window were replayed.')).toBeTruthy();
  });

  it('a replay refused because another is running shows the error as text', async () => {
    const busy = 'a replay is already running <b>try later</b>';
    mockFetch({
      'GET /api/policy': { body: { source: 'built-in', text: LOADED } },
      'POST /api/policy/replay': { status: 429, body: { error: busy } },
    });
    const { container } = render(<Policy />);
    const candidate = (await screen.findByLabelText(/candidate policy/i)) as HTMLTextAreaElement;
    await waitFor(() => expect(candidate.value).toBe(LOADED));
    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    expect((await screen.findByText(busy)).getAttribute('role')).toBe('alert');
    expect(container.querySelector('b')).toBeNull();
    // Not a policy error: the candidate itself is fine.
    expect(screen.queryByLabelText('Policy error')).toBeNull();
    expect(screen.queryByRole('region', { name: 'Replay result' })).toBeNull();
  });
});
