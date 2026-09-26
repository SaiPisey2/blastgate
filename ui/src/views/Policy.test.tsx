import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Policy from './Policy';
import { setCSRF, type ReplayResult } from '../api';
import { mockFetch } from '../test/fetch';

const EVIL = '<img src=x onerror=alert(1)>';

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

// changeNamed finds a change by its whole sentence: the identifier in it
// is set in its own mono span, so the text spans two elements.
function changeNamed(result: HTMLElement, sentence: string): HTMLElement {
  const p = within(result).getByText((_, el) => !!el && el.classList.contains('policy-change-sentence') && el.textContent === sentence);
  return p.closest('li')!;
}

describe('Policy', () => {
  it('shows the loaded policy read-only in a disclosure and replays a candidate with the csrf header', async () => {
    const calls = mockFetch({
      'GET /api/policy': { body: { source: '/etc/blastgate/policy.yaml', text: LOADED } },
      'POST /api/policy/replay': { body: RESULT },
    });
    setCSRF('tok');
    render(<Policy />);

    // The loaded policy, read-only, with where it came from: the summary
    // is visible before the disclosure is ever opened.
    const disclosure = (await screen.findByText('/etc/blastgate/policy.yaml')).closest('details') as HTMLDetailsElement;
    expect(disclosure.open).toBe(false);
    const loaded = screen.getByLabelText('Loaded policy');
    expect(loaded.textContent).toBe(LOADED);
    expect(loaded.tagName).toBe('PRE');
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

    await screen.findByRole('region', { name: 'Replay result' });
    expect(screen.queryByRole('button', { name: /apply/i })).toBeNull();
  });

  it('decisions read in plain words, and an unrecognised one shows raw', async () => {
    const withUnknown: ReplayResult = {
      ...RESULT,
      changed: 3,
      changes: [
        ...RESULT.changes,
        {
          at: '2026-09-26T09:50:00Z',
          request_id: 'r-3',
          verb: 'patch',
          resource: 'services',
          namespace: 'team-a',
          name: 'api',
          rule_before: 'x',
          rule_after: 'y',
          decision_before: 'weird',
          decision_after: 'allow',
        },
      ],
    };
    mockFetch({
      'GET /api/policy': { body: { source: 'built-in', text: LOADED } },
      'POST /api/policy/replay': { body: withUnknown },
    });
    render(<Policy />);
    await screen.findByText('built-in');
    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    const result = await screen.findByRole('region', { name: 'Replay result' });

    expect(within(result).getByText('3 of 412')).toBeTruthy();
    expect(within(result).getByText('decisions would change')).toBeTruthy();

    const first = changeNamed(result, 'Delete the pod web-7d9f8c-abcde');
    expect(within(first).getByText('Allowed → Waited for approval')).toBeTruthy();
    // The identifier inside the sentence is set in mono, as everywhere else.
    expect(within(first).getByText('web-7d9f8c-abcde').className).toContain('mono');

    const second = changeNamed(result, 'Run a command in db-0');
    expect(within(second).getByText('Waited for approval → Denied')).toBeTruthy();

    const third = changeNamed(result, 'Change the service api');
    expect(within(third).getByText('weird → Allowed')).toBeTruthy();
  });

  it('hours outside 1 to 720 are refused before sending', async () => {
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
      'POST /api/policy/replay': { body: { evaluated: 10, changed: 0, skipped: 0, truncated: false, changes: [] } },
    });
    render(<Policy />);
    await screen.findByText('built-in');
    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    expect(await screen.findByText(/no request would have been decided differently/i)).toBeTruthy();
  });

  it('a truncated replay says it covered only the most recent decisions in this window', async () => {
    mockFetch({
      'GET /api/policy': { body: { source: 'built-in', text: LOADED } },
      'POST /api/policy/replay': { body: { ...RESULT, evaluated: 100000, truncated: true } },
    });
    render(<Policy />);
    await screen.findByText('built-in');
    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    const result = await screen.findByRole('region', { name: 'Replay result' });
    expect(within(result).getByText('Only the most recent 100000 decisions in this window were replayed.')).toBeTruthy();
  });

  it('a policy that does not load shows the parser message verbatim, as text', async () => {
    mockFetch({
      'GET /api/policy': { body: { source: 'built-in', text: LOADED } },
      'POST /api/policy/replay': { status: 400, body: { error: PARSE_ERROR } },
    });
    render(<Policy />);
    await screen.findByText('built-in');
    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    const err = await screen.findByLabelText('Policy error');
    expect(err.tagName).toBe('PRE');
    expect(err.textContent).toBe(PARSE_ERROR);
    expect(screen.queryByRole('region', { name: 'Replay result' })).toBeNull();
  });

  it('a replay refused because another is running shows a fixed message, not the server text', async () => {
    const busy = 'a replay is already running <b>try later</b>';
    mockFetch({
      'GET /api/policy': { body: { source: 'built-in', text: LOADED } },
      'POST /api/policy/replay': { status: 429, body: { error: busy } },
    });
    const { container } = render(<Policy />);
    await screen.findByText('built-in');
    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    const err = await screen.findByText('A replay is already running; try again when it finishes.');
    expect(err.getAttribute('role')).toBe('alert');
    expect(container.querySelector('b')).toBeNull();
    expect(screen.queryByText(busy)).toBeNull();
    // Not a policy error: the candidate itself is fine.
    expect(screen.queryByLabelText('Policy error')).toBeNull();
    expect(screen.queryByRole('region', { name: 'Replay result' })).toBeNull();
  });

  it('the try form and its result sit in the two-column grid', async () => {
    mockFetch({ 'GET /api/policy': { body: { source: 'built-in', text: LOADED } } });
    const { container } = render(<Policy />);
    await screen.findByText('built-in');
    expect(container.querySelector('.policy-grid')).toBeTruthy();
    expect(container.querySelector('.policy-grid > .policy-try')).toBeTruthy();
    expect(container.querySelector('.policy-grid > .policy-results')).toBeTruthy();
  });

  it('a stale result disappears once a later replay comes back a 400', async () => {
    let bad = false;
    mockFetch({
      'GET /api/policy': { body: { source: 'built-in', text: LOADED } },
      'POST /api/policy/replay': () => (bad ? { status: 400, body: { error: PARSE_ERROR } } : { body: RESULT }),
    });
    render(<Policy />);
    await screen.findByText('built-in');
    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    await screen.findByRole('region', { name: 'Replay result' });

    bad = true;
    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    await screen.findByLabelText('Policy error');
    expect(screen.queryByRole('region', { name: 'Replay result' })).toBeNull();
  });

  it('a stale result disappears once a later replay comes back a 429', async () => {
    let busy = false;
    mockFetch({
      'GET /api/policy': { body: { source: 'built-in', text: LOADED } },
      'POST /api/policy/replay': () => (busy ? { status: 429, body: { error: 'busy' } } : { body: RESULT }),
    });
    render(<Policy />);
    await screen.findByText('built-in');
    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    await screen.findByRole('region', { name: 'Replay result' });

    busy = true;
    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    await screen.findByText('A replay is already running; try again when it finishes.');
    expect(screen.queryByRole('region', { name: 'Replay result' })).toBeNull();
  });

  it('the loaded policy, the candidate and a parse error render hostile strings as text, never as markup', async () => {
    mockFetch({
      'GET /api/policy': { body: { source: EVIL, text: EVIL } },
      'POST /api/policy/replay': { status: 400, body: { error: EVIL } },
    });
    const { container } = render(<Policy />);

    const disclosure = await waitFor(() => {
      const d = container.querySelector('details.policy-disclosure');
      if (!d) throw new Error('disclosure not yet rendered');
      return d;
    });
    expect(disclosure.querySelector('code')!.textContent).toBe(EVIL);
    expect(screen.getByLabelText('Loaded policy').textContent).toBe(EVIL);

    const candidate = screen.getByLabelText(/candidate policy/i) as HTMLTextAreaElement;
    await waitFor(() => expect(candidate.value).toBe(EVIL));

    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    const err = await screen.findByLabelText('Policy error');
    expect(err.textContent).toBe(EVIL);
    expect(container.querySelector('img')).toBeNull();
  });

  it('a change with hostile strings in its fields renders as text, never as markup', async () => {
    const evilResult: ReplayResult = {
      evaluated: 1,
      changed: 1,
      skipped: 0,
      truncated: false,
      changes: [
        {
          at: '2026-09-26T09:30:00Z',
          request_id: 'r-1',
          verb: 'delete',
          resource: 'pods',
          namespace: EVIL,
          name: EVIL,
          rule_before: EVIL,
          rule_after: EVIL,
          decision_before: EVIL,
          decision_after: EVIL,
        },
      ],
    };
    mockFetch({
      'GET /api/policy': { body: { source: 'built-in', text: LOADED } },
      'POST /api/policy/replay': { body: evilResult },
    });
    const { container } = render(<Policy />);
    await screen.findByText('built-in');
    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    const result = await screen.findByRole('region', { name: 'Replay result' });
    expect(result.textContent).toContain(EVIL);
    expect(container.querySelector('img')).toBeNull();
  });

  it('the 64 KiB counter warns and refuses a candidate over the limit', async () => {
    const calls = mockFetch({
      'GET /api/policy': { body: { source: 'built-in', text: '' } },
      'POST /api/policy/replay': { body: RESULT },
    });
    const { container } = render(<Policy />);
    await screen.findByText('built-in');
    const candidate = screen.getByLabelText(/candidate policy/i) as HTMLTextAreaElement;

    expect(container.querySelector('.policy-counter')!.textContent).toBe('0 / 65,536 bytes');
    expect(container.querySelector('.policy-counter-danger')).toBeNull();

    // fireEvent, not userEvent.type: 70,000 keystrokes would time out the
    // test, and this only needs the byte count to be over the limit.
    const over = 'a'.repeat(70_000);
    fireEvent.change(candidate, { target: { value: over } });
    await waitFor(() => expect(container.querySelector('.policy-counter')!.textContent).toBe('70,000 / 65,536 bytes'));
    expect(container.querySelector('.policy-counter-danger')).toBeTruthy();

    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    expect(await screen.findByText(/larger than 64 KiB/i)).toBeTruthy();
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });
});
