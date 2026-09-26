// @ts-expect-error -- this package has no @types/node; Vitest runs on Node.
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, createEvent, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DecisionPanel, { type DecisionPanelProps } from './DecisionPanel';
import { setCSRF, type ApprovalDetail, type ApprovalSummary } from '../api';
import { ARM_MS } from '../lib/friction';
import { mockFetch, type Call } from '../test/fetch';
import { detail, ID1, ID2, impact, summary } from '../test/fixtures';

afterEach(() => {
  cleanup();
  setCSRF('');
  vi.useRealTimers();
});

// Read from disk (Vitest runs from ui/): it stubs CSS imports, even
// ?raw, to empty strings.
const componentsCSS = readFileSync('src/styles/components.css', 'utf8');

const EVIL = '<img src=x onerror=alert(1)>';
const SELF_REASON = "You can't approve a request made on your behalf";
const GONE = 'This request is no longer waiting.';

// A reversible, measured patch: the calmest thing that can be held.
const reversible = summary({
  rule: 'hold-writes',
  verb: 'patch',
  resource: 'deployments',
  name: 'web',
  summary: 'REVERSIBLE, 1 object',
  class: 'REVERSIBLE',
  data_destroyed: 0,
});
const reversibleImpact = impact({ class: 'REVERSIBLE', dataDestroyed: 0, undo: 'objects', effects: [{ kind: 'changed', object: 'apps/Deployment/demo/web' }] });

function routes(approve: { status?: number; body?: unknown } = { body: {} }) {
  return mockFetch({
    [`POST /api/approvals/${ID1}/approve`]: approve,
    [`POST /api/approvals/${ID1}/deny`]: { body: {} },
    [`POST /api/approvals/${ID2}/approve`]: { body: {} },
  });
}

const posts = (calls: Call[]) => calls.filter((c) => c.method === 'POST').map((c) => c.url);

function renderPanel(over: Partial<DecisionPanelProps> & { summary: ApprovalSummary }) {
  const onDecided = vi.fn();
  const onRetry = vi.fn();
  const props: DecisionPanelProps = { me: 'bob', onRetry, onDecided, ...over };
  const utils = render(<DecisionPanel {...props} />);
  return { ...utils, onDecided, onRetry, props };
}

const withDetail = (s: ApprovalSummary, i = impact()): { summary: ApprovalSummary; detail: ApprovalDetail } => ({ summary: s, detail: detail(s, i) });

const approveButton = () => screen.getByRole('button', { name: /^approve$/i }) as HTMLButtonElement;
const denyButton = () => screen.getByRole('button', { name: /^deny$/i }) as HTMLButtonElement;
const typedField = () => screen.getByLabelText(/to approve, type/i) as HTMLInputElement;

describe('DecisionPanel friction levels', () => {
  it('a reversible measured action needs one confirm', async () => {
    // fireEvent, not userEvent, while the clock is fake: Testing Library's
    // async wrapper waits on a real setTimeout that only Jest's fake timers
    // know how to advance.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const calls = routes();
    setCSRF('tok');
    const { onDecided } = renderPanel(withDetail(reversible, reversibleImpact));

    expect(screen.queryByRole('textbox')).toBeNull();
    fireEvent.click(approveButton());
    // The first click only opens the confirm step; nothing is sent yet.
    expect(posts(calls)).toEqual([]);
    const confirm = screen.getByRole('button', { name: /confirm/i }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    act(() => vi.advanceTimersByTime(ARM_MS - 1));
    expect(confirm.disabled).toBe(true);
    fireEvent.click(confirm);
    expect(posts(calls)).toEqual([]);
    act(() => vi.advanceTimersByTime(1));
    expect(confirm.disabled).toBe(false);

    vi.useRealTimers();
    await userEvent.click(confirm);
    await waitFor(() => expect(onDecided).toHaveBeenCalledWith(ID1, 'approved'));
    const post = calls.find((c) => c.method === 'POST')!;
    expect(post.url).toBe(`/api/approvals/${ID1}/approve`);
    expect(post.headers['x-blastgate-csrf']).toBe('tok');
    expect(posts(calls)).toEqual([`/api/approvals/${ID1}/approve`]);
  });

  it('a click that lands on confirm before it arms is ignored', async () => {
    const calls = routes();
    renderPanel(withDetail(reversible, reversibleImpact));
    await userEvent.click(approveButton());
    // A double-click on Approve lands its second click here.
    await userEvent.click(screen.getByRole('button', { name: /confirm/i }));
    expect(posts(calls)).toEqual([]);
  });

  it('cancel backs out of the confirm step without deciding', async () => {
    const calls = routes();
    renderPanel(withDetail(reversible, reversibleImpact));
    await userEvent.click(approveButton());
    await userEvent.click(screen.getByRole('button', { name: /cancel/i }));
    // The step collapses (a short exit), and focus goes back to Deny.
    await waitFor(() => expect(screen.queryByRole('button', { name: /confirm/i })).toBeNull());
    expect(document.activeElement).toBe(denyButton());
    expect(posts(calls)).toEqual([]);
  });

  it('a compensable action shows how to undo before confirming', async () => {
    const s = summary({ class: 'COMPENSABLE', data_destroyed: 0, verb: 'patch', resource: 'deployments', name: 'web', summary: 'COMPENSABLE, 1 object' });
    const i = impact({ class: 'COMPENSABLE', dataDestroyed: 0, undo: 'scale deployments/web back to 3', effects: [{ kind: 'changed', object: 'apps/Deployment/demo/web' }] });
    const calls = routes();
    const { onDecided } = renderPanel(withDetail(s, i));
    expect(screen.getByText('Needs a follow-up to undo')).toBeTruthy();
    expect(screen.queryByRole('textbox')).toBeNull();

    await userEvent.click(approveButton());
    const step = screen.getByRole('group', { name: /confirm/i });
    expect(within(step).getByText(/scale deployments\/web back to 3/)).toBeTruthy();
    const confirm = within(step).getByRole('button', { name: /confirm/i }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    await waitFor(() => expect(confirm.disabled).toBe(false));
    await userEvent.click(confirm);
    await waitFor(() => expect(onDecided).toHaveBeenCalledWith(ID1, 'approved'));
    expect(posts(calls)).toEqual([`/api/approvals/${ID1}/approve`]);
  });

  it('a plain reversible confirm step does not show undo text', async () => {
    routes();
    renderPanel(withDetail(reversible, reversibleImpact));
    await userEvent.click(approveButton());
    const step = screen.getByRole('group', { name: /confirm/i });
    expect(within(step).queryByText(/undo/i)).toBeNull();
  });

  it('data destruction needs the full target typed', async () => {
    const calls = routes();
    const { onDecided } = renderPanel(withDetail(summary()));
    expect(screen.getByText('Cannot be undone')).toBeTruthy();
    const field = typedField();
    expect(within(field.closest('.typed-confirm')!).getByText('demo/data').className).toContain('mono');
    expect(approveButton().disabled).toBe(true);
    await userEvent.type(field, 'demo');
    expect(approveButton().disabled).toBe(true);
    await userEvent.type(field, '/data');
    expect(approveButton().disabled).toBe(false);
    await userEvent.click(approveButton());
    await waitFor(() => expect(onDecided).toHaveBeenCalledWith(ID1, 'approved'));
    expect(posts(calls)).toEqual([`/api/approvals/${ID1}/approve`]);
  });

  it('the summary alone decides that typing is required', async () => {
    // The detail disagrees (nothing destroyed); the summary wins, so a stale
    // or partial detail can never switch the typed confirmation off.
    renderPanel(withDetail(summary(), impact({ dataDestroyed: 0 })));
    expect(typedField()).toBeTruthy();
  });

  it('a detail that says unmeasured is enough to demand typing', async () => {
    const s = summary({ class: 'COMPENSABLE', data_destroyed: 0 });
    renderPanel(withDetail(s, impact({ class: 'COMPENSABLE', measured: false, dataDestroyed: 0 })));
    expect(typedField()).toBeTruthy();
    expect(screen.getByText('Impact unknown')).toBeTruthy();
  });

  for (const [label, over] of [
    ['TERMINAL', { class: 'TERMINAL', data_destroyed: 0 }],
    ['AUTHORITY', { class: 'AUTHORITY', data_destroyed: 0, verb: 'create', resource: 'clusterrolebindings' }],
    ['an empty class', { class: '', data_destroyed: 0 }],
    ['SOMETHING_NEW', { class: 'SOMETHING_NEW', data_destroyed: 0 }],
    ['REVERSIBLE unmeasured', { class: 'REVERSIBLE', data_destroyed: 0, measured: false }],
  ] as const) {
    it(`terminal, authority, unknown and unmeasured all need typing: ${label}`, async () => {
      const s = summary(over);
      const calls = routes();
      renderPanel(withDetail(s, impact({ class: over.class, dataDestroyed: 0, measured: s.measured })));
      const field = typedField();
      expect(approveButton().disabled).toBe(true);
      // Past any arming delay, and still inert without the target.
      await new Promise((r) => setTimeout(r, ARM_MS + 50));
      await userEvent.click(approveButton());
      expect(posts(calls)).toEqual([]);
      await userEvent.type(field, 'demo/dat');
      expect(approveButton().disabled).toBe(true);
      await userEvent.type(field, 'a');
      expect(approveButton().disabled).toBe(false);
    });
  }

  it('a missing measured field fails closed', () => {
    const { measured: _drop, ...rest } = summary({ class: 'COMPENSABLE', data_destroyed: 0 });
    const s = rest as ApprovalSummary;
    renderPanel(withDetail(s, impact({ class: 'COMPENSABLE', measured: true, dataDestroyed: 0 })));
    expect(typedField()).toBeTruthy();
    expect(screen.getByText('Impact unknown')).toBeTruthy();
  });
});

describe('DecisionPanel typed field', () => {
  it('paste is blocked in the typed field', async () => {
    renderPanel(withDetail(summary()));
    const field = typedField();
    const ev = createEvent.paste(field, { clipboardData: { getData: () => 'demo/data' } });
    fireEvent(field, ev);
    expect(ev.defaultPrevented).toBe(true);

    field.focus();
    await userEvent.paste('demo/data');
    expect(field.value).toBe('');
    expect(approveButton().disabled).toBe(true);
  });

  it('dropping text into the typed field is blocked too', () => {
    renderPanel(withDetail(summary()));
    const field = typedField();
    const ev = createEvent.drop(field);
    fireEvent(field, ev);
    expect(ev.defaultPrevented).toBe(true);
  });

  it('the typed field is not autocompleted or spellchecked', () => {
    renderPanel(withDetail(summary()));
    const field = typedField();
    expect(field.getAttribute('autocomplete')).toBe('off');
    expect(field.getAttribute('spellcheck')).toBe('false');
  });

  it('cluster-scoped unnamed requests still need typing', async () => {
    const s = summary({ verb: 'deletecollection', resource: 'persistentvolumes', namespace: '', name: '', data_destroyed: 3 });
    renderPanel(withDetail(s, impact({ dataDestroyed: 3 })));
    const field = typedField();
    expect(within(field.closest('.typed-confirm')!).getByText('persistentvolumes')).toBeTruthy();
    expect(approveButton().disabled).toBe(true);
    await userEvent.type(field, 'persistentvolumes');
    expect(approveButton().disabled).toBe(false);
  });
});

describe('DecisionPanel focus and keys', () => {
  it('deny has the default focus', () => {
    renderPanel(withDetail(reversible, reversibleImpact));
    expect(document.activeElement).toBe(denyButton());
    expect(document.activeElement).not.toBe(approveButton());
  });

  it('deny has the default focus before the detail loads, too', () => {
    renderPanel({ summary: reversible });
    expect(document.activeElement).toBe(denyButton());
  });

  it('the typed field takes the default focus when typing is required, never approve', () => {
    renderPanel(withDetail(summary()));
    expect(document.activeElement).toBe(typedField());
    expect(document.activeElement).not.toBe(approveButton());
  });

  for (const [chord, keys] of [
    ['meta', '{Meta>}{Enter}{/Meta}'],
    ['ctrl', '{Control>}{Enter}{/Control}'],
  ] as const) {
    it(`approve needs a chord after typing (${chord})`, async () => {
      const calls = routes();
      const { onDecided } = renderPanel(withDetail(summary()));
      const field = typedField();
      // Before the value is valid, nothing submits: not Enter, not a chord.
      await userEvent.type(field, 'demo/dat');
      await userEvent.keyboard('{Enter}{Meta>}{Enter}{/Meta}{Control>}{Enter}{/Control}');
      expect(posts(calls)).toEqual([]);
      // Valid, and a plain Enter still does nothing.
      await userEvent.type(field, 'a');
      expect(field.value).toBe('demo/data');
      await userEvent.keyboard('{Enter}');
      await new Promise((r) => setTimeout(r, 20));
      expect(posts(calls)).toEqual([]);
      expect(onDecided).not.toHaveBeenCalled();
      // The chord approves, once.
      await userEvent.keyboard(keys);
      await waitFor(() => expect(onDecided).toHaveBeenCalledWith(ID1, 'approved'));
      await userEvent.keyboard(keys);
      expect(posts(calls)).toEqual([`/api/approvals/${ID1}/approve`]);
    });
  }

  it('a bare a or y key never approves', async () => {
    const calls = routes();
    renderPanel(withDetail(reversible, reversibleImpact));
    await userEvent.keyboard('aAyY');
    // Not even with the confirm step open and armed.
    await userEvent.click(approveButton());
    await new Promise((r) => setTimeout(r, ARM_MS + 50));
    await userEvent.keyboard('aAyY');
    expect(posts(calls)).toEqual([]);
  });
});

describe('DecisionPanel guards', () => {
  it('self approval is refused', async () => {
    const s = { ...reversible, human: 'alice' };
    const calls = routes();
    const { onDecided } = renderPanel({ ...withDetail(s, reversibleImpact), me: 'alice' });
    const approve = approveButton();
    expect(approve.disabled).toBe(true);
    expect(screen.getByText(SELF_REASON)).toBeTruthy();
    // The reason is tied to the button, not just nearby.
    const described = approve.getAttribute('aria-describedby') ?? '';
    expect(described.split(' ').map((id) => document.getElementById(id)?.textContent).join(' ')).toContain(SELF_REASON);
    await userEvent.click(approve);
    expect(posts(calls)).toEqual([]);

    await userEvent.click(denyButton());
    await waitFor(() => expect(onDecided).toHaveBeenCalledWith(ID1, 'denied'));
    expect(posts(calls)).toEqual([`/api/approvals/${ID1}/deny`]);
  });

  it('self approval stays refused even after the target is typed', async () => {
    const s = summary({ human: 'alice' });
    const calls = routes();
    renderPanel({ ...withDetail(s), me: 'alice' });
    await userEvent.type(typedField(), 'demo/data');
    expect(approveButton().disabled).toBe(true);
    await userEvent.keyboard('{Enter}');
    await userEvent.keyboard('{Meta>}{Enter}{/Meta}');
    expect(posts(calls)).toEqual([]);
  });

  it('unmeasured shows Unknown, never zero', () => {
    const s = summary({ class: 'TERMINAL', measured: false, data_destroyed: 0, verb: 'create', resource: 'pods/exec', name: 'db-0', summary: 'not measured' });
    const { container } = renderPanel(withDetail(s, impact({ measured: false, dataDestroyed: 0, effects: [] })));
    const facts = screen.getByRole('list', { name: /facts/i });
    const affects = within(facts).getByText('What it affects').closest('li')!;
    expect(within(affects).getByText('Unknown')).toBeTruthy();
    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
    const zeros: string[] = [];
    for (let n = walker.nextNode(); n; n = walker.nextNode()) if ((n.nodeValue ?? '').trim() === '0') zeros.push(n.parentElement?.outerHTML ?? '');
    expect(zeros).toEqual([]);
  });

  it('approve waits for the detail', () => {
    const { rerender, props } = renderPanel({ summary: reversible });
    expect(approveButton().disabled).toBe(true);
    // Before the detail, "What it affects" is the summary's own line.
    expect(screen.getByText('REVERSIBLE, 1 object')).toBeTruthy();
    rerender(<DecisionPanel {...props} detail={detail(reversible, reversibleImpact)} />);
    expect(approveButton().disabled).toBe(false);
    expect(screen.getByText('1 object')).toBeTruthy();
    expect(screen.getByText('Snapshot kept')).toBeTruthy();
  });

  it('a failed detail shows the error with retry', async () => {
    const { onRetry } = renderPanel({ summary: reversible, detailError: 'store unavailable' });
    expect(screen.getByText(/store unavailable/)).toBeTruthy();
    expect(approveButton().disabled).toBe(true);
    await userEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});

describe('DecisionPanel server outcomes', () => {
  for (const status of [409, 404]) {
    it(`a ${status} means the request is gone`, async () => {
      routes({ status, body: { error: 'not pending' } });
      const { onDecided } = renderPanel(withDetail(summary()));
      await userEvent.type(typedField(), 'demo/data');
      await userEvent.click(approveButton());
      await waitFor(() => expect(onDecided).toHaveBeenCalledWith(ID1, 'gone'));
      expect(screen.getByText(GONE)).toBeTruthy();
      expect(screen.queryByRole('button', { name: /^approve$/i })).toBeNull();
    });
  }

  it('any other error keeps the panel and shows the message as text', async () => {
    routes({ status: 500, body: { error: EVIL } });
    const { onDecided, container } = renderPanel(withDetail(reversible, reversibleImpact));
    await userEvent.click(approveButton());
    const confirm = screen.getByRole('button', { name: /confirm/i }) as HTMLButtonElement;
    await waitFor(() => expect(confirm.disabled).toBe(false));
    await userEvent.click(confirm);
    expect(await screen.findByText(EVIL)).toBeTruthy();
    expect(container.querySelector('img')).toBeNull();
    expect(onDecided).not.toHaveBeenCalled();
    expect(approveButton()).toBeTruthy();
    expect(denyButton()).toBeTruthy();
  });

  it('a decided approval shows who decided and no buttons', () => {
    const s = { ...reversible, status: 'approved' };
    const d = { ...detail(s, reversibleImpact), decided_by: 'carol', decided: '2026-09-26T10:00:00Z' };
    renderPanel({ summary: s, detail: d });
    expect(screen.getByText(/approved by carol/i)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /approve/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /deny/i })).toBeNull();
    expect(screen.queryByRole('textbox')).toBeNull();
  });

  it('a status outside the map is shown raw, and consumed reads plainly', () => {
    renderPanel({ summary: { ...reversible, status: 'consumed' } });
    expect(screen.getByText(/approved and carried out/i)).toBeTruthy();
    cleanup();
    renderPanel({ summary: { ...reversible, status: 'toString' } });
    expect(screen.getByText(/^toString\.$/)).toBeTruthy();
  });
});

describe('DecisionPanel rendering', () => {
  it('reads top to bottom: position, tag, question, why, facts', () => {
    renderPanel({ ...withDetail(summary()), position: { index: 1, total: 3 } });
    const order = [
      screen.getByText('1 of 3 waiting for you'),
      screen.getByText('Cannot be undone'),
      screen.getByRole('heading'),
      screen.getByText('Its data would be destroyed with it.'),
      screen.getByRole('list', { name: /facts/i }),
    ];
    for (let i = 1; i < order.length; i++) {
      expect(order[i - 1].compareDocumentPosition(order[i]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    }
    expect(screen.getByRole('heading').textContent).toBe('coding-agent wants to delete the volume claim demo/data');
    expect(within(screen.getByRole('heading')).getByText('demo/data').className).toContain('mono');
  });

  it('the facts are who asked, what it affects and undo', () => {
    renderPanel(withDetail(summary()));
    const facts = screen.getByRole('list', { name: /facts/i });
    const fact = (label: string) => within(facts).getByText(label).closest('li')!;
    expect(within(fact('Asked by')).getByText('alice')).toBeTruthy();
    expect(within(fact('What it affects')).getByText('2 objects, 1 volume destroyed')).toBeTruthy();
    expect(within(fact('Undo')).getByText('None')).toBeTruthy();
  });

  it('undo reads plainly for every value', () => {
    for (const [undo, text] of [
      ['objects', 'Snapshot kept'],
      ['none', 'None'],
      ['', 'Unknown'],
      ['recreate from git', 'recreate from git'],
    ]) {
      renderPanel(withDetail(reversible, { ...reversibleImpact, undo }));
      const facts = screen.getByRole('list', { name: /facts/i });
      expect(within(within(facts).getByText('Undo').closest('li')!).getByText(text)).toBeTruthy();
      cleanup();
    }
  });

  it('the question is 28 in the one-at-a-time layout', () => {
    renderPanel({ ...withDetail(summary()), position: { index: 2, total: 5 } });
    expect(screen.getByRole('heading').className).toContain('decision-q-lg');
    cleanup();
    renderPanel(withDetail(summary()));
    expect(screen.getByRole('heading').className).not.toContain('decision-q-lg');
  });

  it('show the command expands the action text; show details links to the route', async () => {
    const s = summary({ verb: 'create', resource: 'pods/exec', namespace: 'team-a', name: 'db-0', class: 'TERMINAL', data_destroyed: 0 });
    const d: ApprovalDetail = {
      ...detail(s, impact({ effects: [], dataDestroyed: 0 })),
      action: { verb: 'create', path: '/api/v1/namespaces/team-a/pods/db-0/exec', query: { command: ['psql', '-c', "drop table users; -- it's gone"] } },
    };
    renderPanel({ summary: s, detail: d });
    const toggle = screen.getByRole('button', { name: /show the command/i });
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    await userEvent.click(toggle);
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    const block = document.getElementById(toggle.getAttribute('aria-controls')!)!;
    expect(block.className).toContain('mono');
    expect(block.textContent).toContain(`$ psql -c 'drop table users; -- it'\\''s gone'`);
    const link = screen.getByRole('link', { name: /show details/i });
    expect(link.getAttribute('href')).toBe(`#/approvals/${ID1}`);
  });

  it('a standalone panel has no link to itself', () => {
    renderPanel({ ...withDetail(summary()), standalone: true });
    expect(screen.queryByRole('link', { name: /show details/i })).toBeNull();
  });

  it('long names wrap in the decision panel', () => {
    const long = 'n'.repeat(253);
    renderPanel(withDetail(summary({ name: long })));
    const carriers = screen.getAllByText(`demo/${long}`);
    expect(carriers.length).toBeGreaterThan(0);
    for (const el of carriers) expect(el.classList.contains('mono')).toBe(true);
    // .mono is the class that lets an identifier break anywhere.
    expect(componentsCSS).toMatch(/\.mono\s*\{[^}]*overflow-wrap:\s*anywhere/);
  });

  it('hostile names stay text', () => {
    const s = summary({ name: EVIL, namespace: EVIL, agent: EVIL, human: EVIL, rule: EVIL, summary: EVIL, class: EVIL });
    const { container } = renderPanel({ summary: s, detail: detail(s, impact({ undo: EVIL, class: EVIL })) });
    expect(screen.getAllByText(EVIL, { exact: false }).length).toBeGreaterThan(0);
    expect(screen.getByRole('heading').textContent).toContain(`${EVIL} wants to`);
    expect(container.querySelector('img')).toBeNull();
    expect(container.innerHTML).toContain('&lt;img');
  });
});

describe('DecisionPanel retargeting and refetch flaps', () => {
  const base = (over: Partial<DecisionPanelProps> & { summary: ApprovalSummary }): DecisionPanelProps => ({
    me: 'bob',
    onRetry: vi.fn(),
    onDecided: vi.fn(),
    ...over,
  });

  it('an id change resets the typed value, even for the same target', async () => {
    const calls = routes();
    const s1 = summary();
    const props = base({ summary: s1, detail: detail(s1, impact()) });
    const { rerender } = render(<DecisionPanel {...props} />);
    await userEvent.type(typedField(), 'demo/data');
    expect(approveButton().disabled).toBe(false);
    const s2 = summary({ id: ID2 });
    rerender(<DecisionPanel {...props} summary={s2} detail={detail(s2, impact())} />);
    expect(typedField().value).toBe('');
    expect(approveButton().disabled).toBe(true);
    await userEvent.click(approveButton());
    expect(posts(calls)).toEqual([]);
  });

  it('an id change closes an armed confirm step', async () => {
    const calls = routes();
    const props = base(withDetail(reversible, reversibleImpact));
    const { rerender } = render(<DecisionPanel {...props} />);
    await userEvent.click(approveButton());
    await waitFor(() => expect((screen.getByRole('button', { name: /confirm/i }) as HTMLButtonElement).disabled).toBe(false));
    const s2 = { ...reversible, id: ID2 };
    rerender(<DecisionPanel {...props} summary={s2} detail={detail(s2, reversibleImpact)} />);
    expect(screen.queryByRole('button', { name: /confirm approval/i })).toBeNull();
    expect(posts(calls)).toEqual([]);
  });

  it('a POST in flight reports its own id, even after the panel moved on', async () => {
    let release!: () => void;
    const calls = mockFetch({
      [`POST /api/approvals/${ID1}/approve`]: () => new Promise((r) => (release = () => r({ body: {} }))),
    });
    const onDecided = vi.fn();
    const s1 = summary();
    const props = base({ summary: s1, detail: detail(s1, impact()), onDecided });
    const { rerender } = render(<DecisionPanel {...props} />);
    await userEvent.type(typedField(), 'demo/data');
    await userEvent.click(approveButton());
    const s2 = summary({ id: ID2 });
    rerender(<DecisionPanel {...props} summary={s2} detail={detail(s2, impact())} />);
    await act(async () => release());
    await waitFor(() => expect(onDecided).toHaveBeenCalledWith(ID1, 'approved'));
    expect(onDecided).not.toHaveBeenCalledWith(ID2, expect.anything());
    expect(posts(calls)).toEqual([`/api/approvals/${ID1}/approve`]);
    expect(approveButton().disabled).toBe(true);
    expect(typedField().value).toBe('');
  });

  it('a detail for another id keeps Approve disabled', async () => {
    const calls = routes();
    render(<DecisionPanel {...base({ summary: reversible, detail: detail({ ...reversible, id: ID2 }, reversibleImpact) })} />);
    expect(approveButton().disabled).toBe(true);
    await userEvent.click(approveButton());
    expect(screen.queryByRole('button', { name: /confirm/i })).toBeNull();
    expect(posts(calls)).toEqual([]);
  });

  it('a typed match does not survive a detail flap (typed, confirm, typed)', async () => {
    const calls = routes();
    // Measured summary, unmeasured detail: typing comes only from the detail,
    // so clearing the detail for a refetch drops to a confirm level and back.
    const unmeasured = () => detail(reversible, { ...reversibleImpact, measured: false });
    const props = base({ summary: reversible, detail: unmeasured() });
    const { rerender } = render(<DecisionPanel {...props} />);
    await userEvent.type(typedField(), 'demo/web');
    expect(approveButton().disabled).toBe(false);
    rerender(<DecisionPanel {...props} detail={undefined} />);
    expect(screen.queryByLabelText(/to approve, type/i)).toBeNull();
    rerender(<DecisionPanel {...props} detail={unmeasured()} />);
    expect(typedField().value).toBe('');
    expect(approveButton().disabled).toBe(true);
    await userEvent.click(approveButton());
    await userEvent.keyboard('{Control>}{Enter}{/Control}');
    expect(posts(calls)).toEqual([]);
  });

  it('a confirm step waits ARM_MS again after a detail flap', () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const calls = routes();
    const props = base(withDetail(reversible, reversibleImpact));
    const { rerender } = render(<DecisionPanel {...props} />);
    fireEvent.click(approveButton());
    act(() => vi.advanceTimersByTime(ARM_MS));
    expect((screen.getByRole('button', { name: /confirm/i }) as HTMLButtonElement).disabled).toBe(false);
    rerender(<DecisionPanel {...props} detail={undefined} />);
    act(() => vi.advanceTimersByTime(1000));
    rerender(<DecisionPanel {...props} detail={detail(reversible, reversibleImpact)} />);
    // The step closed with the flap; reopening it starts the clock over.
    expect(screen.queryByRole('button', { name: /confirm approval/i })).toBeNull();
    fireEvent.click(approveButton());
    const confirm = screen.getByRole('button', { name: /confirm/i }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    act(() => vi.advanceTimersByTime(ARM_MS - 1));
    expect(confirm.disabled).toBe(true);
    fireEvent.click(confirm);
    act(() => vi.advanceTimersByTime(1));
    expect(confirm.disabled).toBe(false);
    expect(posts(calls)).toEqual([]);
  });

  it('focus stays off Confirm when it arms', async () => {
    routes();
    renderPanel(withDetail(reversible, reversibleImpact));
    await userEvent.click(approveButton());
    const confirm = screen.getByRole('button', { name: /confirm/i }) as HTMLButtonElement;
    await waitFor(() => expect(confirm.disabled).toBe(false));
    await new Promise((r) => setTimeout(r, 20));
    expect(document.activeElement).not.toBe(confirm);
    expect(document.activeElement).toBe(approveButton());
  });

  it('a held Enter on Approve does not approve', async () => {
    const calls = routes();
    renderPanel(withDetail(reversible, reversibleImpact));
    approveButton().focus();
    await userEvent.keyboard('{Enter}');
    await new Promise((r) => setTimeout(r, ARM_MS + 50));
    // Key-repeat lands wherever focus is; it must still be on Approve.
    await userEvent.keyboard('{Enter}{Enter}{Enter}');
    expect(posts(calls)).toEqual([]);
  });

  it('a double click at the typed level sends one POST', async () => {
    const calls = routes();
    renderPanel(withDetail(summary()));
    await userEvent.type(typedField(), 'demo/data');
    const b = approveButton();
    fireEvent.click(b);
    fireEvent.click(b);
    await userEvent.dblClick(b).catch(() => {});
    await new Promise((r) => setTimeout(r, 30));
    expect(posts(calls)).toEqual([`/api/approvals/${ID1}/approve`]);
  });

  it('repeated chords in one tick send one POST', async () => {
    const calls = routes();
    renderPanel(withDetail(summary()));
    const f = typedField();
    await userEvent.type(f, 'demo/data');
    fireEvent.keyDown(f, { key: 'Enter', ctrlKey: true });
    fireEvent.keyDown(f, { key: 'Enter', ctrlKey: true });
    fireEvent.keyDown(f, { key: 'Enter', metaKey: true });
    await new Promise((r) => setTimeout(r, 30));
    expect(posts(calls)).toEqual([`/api/approvals/${ID1}/approve`]);
  });
});

describe('DecisionPanel disabled reasons', () => {
  const describedText = (el: HTMLElement) =>
    (el.getAttribute('aria-describedby') ?? '')
      .split(' ')
      .filter(Boolean)
      .map((id) => document.getElementById(id)?.textContent ?? '')
      .join(' | ');

  it('at the typed level Approve points at what to type', async () => {
    renderPanel(withDetail(summary()));
    const text = describedText(approveButton());
    expect(text).toContain('To approve, type demo/data');
    expect(text).toContain('⌘/Ctrl+Enter to approve');
    await userEvent.type(typedField(), 'demo/data');
    expect(describedText(approveButton())).not.toContain('To approve, type');
  });

  it('after a detail error Approve points at the error', () => {
    renderPanel({ summary: reversible, detailError: 'store unavailable' });
    expect(describedText(approveButton())).toContain('store unavailable');
  });

  it('while the detail loads Approve says so', () => {
    renderPanel({ summary: reversible });
    expect(describedText(approveButton())).toMatch(/once blastgate has loaded/);
  });
});
