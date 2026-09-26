import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Waiting, { resetLastDecision } from './views/Waiting';
import Details from './views/Details';
import Activity, { resetOutsideNotice } from './views/Activity';
import Outside from './views/Outside';
import Agents from './views/Agents';
import Policy from './views/Policy';
import { mockFetch } from './test/fetch';
import { renderWithMotion } from './test/motion';
import { setMedia } from './test/media';
import { bypassRow, detail, feedRow, ID1, impact, session, summary } from './test/fixtures';
import type { ApprovalDetail } from './api';

afterEach(() => {
  cleanup();
  resetLastDecision();
  resetOutsideNotice();
});

// Agents choose object names and command lines, so anything the API
// returns is attacker-controlled text. It must reach the page as text
// nodes: if any of it were parsed as HTML, this payload would create an
// <img> whose onerror runs script inside the approver's session.
const EVIL = '<img src=x onerror=alert(1)>';
// The same payload without slashes, so it survives being split into an
// engine object string's group/Kind/namespace/name parts.
const NS = EVIL.replace(/\//g, '');

// clean asserts nothing hostile became markup, and that the literal text
// is on the page as text.
function clean(root: HTMLElement) {
  expect(root.querySelector('img')).toBeNull();
  expect(root.querySelector('[onerror]')).toBeNull();
  expect(root.textContent).toContain(EVIL);
}

// hostileSummary puts the payload in every string field a summary has.
const hostileSummary = () =>
  summary({ rule: EVIL, human: EVIL, agent: EVIL, verb: EVIL, resource: EVIL, namespace: EVIL, name: EVIL, summary: EVIL, class: EVIL });

function hostileDetail(status = 'pending'): ApprovalDetail {
  const s = { ...hostileSummary(), status };
  return {
    ...detail(
      s,
      impact({
        class: EVIL,
        undo: EVIL,
        reason: EVIL,
        effects: [
          { kind: EVIL, object: EVIL, explanation: EVIL },
          { kind: 'destroys', object: `apps/Deployment/${NS}/${NS}`, explanation: EVIL },
          { kind: 'destroys', object: `apps/ReplicaSet/${NS}/${NS}-1`, explanation: EVIL },
          { kind: 'destroys-data', object: `PersistentVolume//${NS}`, explanation: EVIL },
        ],
        endpointsLeft: { [EVIL]: 0 },
        pdbViolations: [EVIL],
      }),
    ),
    action: { verb: EVIL, path: EVIL, rawQuery: EVIL, query: { command: [EVIL, EVIL] } },
    decided_by: EVIL,
  };
}

describe('hostile text', () => {
  it('the Waiting list and its decision panel render hostile names as text', async () => {
    setMedia('(min-width: 900px)', true);
    const s = hostileSummary();
    mockFetch({
      'GET /api/approvals?status=pending': { body: [s] },
      [`GET /api/approvals/${s.id}`]: { body: hostileDetail() },
    });
    const { container } = renderWithMotion(<Waiting me="bob" />);
    const row = await screen.findByRole('option');
    // The row: the literal sentence and "who · when".
    expect(row.textContent).toContain(EVIL);
    const panel = screen.getByRole('article');
    // Wait for the detail: its undo text is hostile too.
    await within(panel).findByRole('button', { name: 'Show the command' });
    const undo = within(panel).getByText('Undo').closest('li')!;
    expect(undo.querySelector('.fact-value')!.textContent).toBe(EVIL);
    // The typed target is namespace/name: still literal text.
    expect(panel.textContent).toContain(`${EVIL}/${EVIL}`);
    await userEvent.click(within(panel).getByRole('button', { name: 'Show the command' }));
    expect(panel.querySelector('pre')!.textContent).toContain(EVIL);
    clean(container);
  });

  it('Details renders a hostile question, tree, command and decider as text', async () => {
    mockFetch({ [`GET /api/approvals/${ID1}`]: { body: hostileDetail('approved') } });
    const { container } = renderWithMotion(<Details id={ID1} me="bob" />);
    const card = await screen.findByRole('article');
    expect(within(card).getByText(`Approved by ${EVIL}.`, { exact: false })).toBeTruthy();
    expect(screen.getByLabelText('Command').textContent).toContain(EVIL);
    const tree = screen.getByRole('tree');
    // Unparseable object, explanations, services and budgets.
    await waitFor(() => expect(within(tree).getAllByText(EVIL, { exact: false }).length).toBeGreaterThanOrEqual(1));
    expect(container.querySelector('[aria-label="Services left with no backends"]')!.textContent).toContain(EVIL);
    expect(container.querySelector('[aria-label="Disruption budgets broken"]')!.textContent).toContain(EVIL);
    // Parsed names too, drawn from the object string's parts.
    expect(within(tree).getAllByText(NS, { exact: false }).length).toBeGreaterThanOrEqual(1);
    clean(container);
  });

  it('Activity renders hostile rows as text', async () => {
    mockFetch({
      'GET /api/bypass': { body: [] },
      'GET /api/feed': {
        body: [feedRow({ name: EVIL, namespace: EVIL, rule: EVIL, human: EVIL, agent: EVIL, resource: EVIL, subresource: EVIL, verb: EVIL, class: EVIL, outcome: EVIL })],
      },
    });
    const { container } = render(<Activity />);
    await waitFor(() => expect(screen.getByRole('log').textContent).toContain(EVIL));
    clean(container);
  });

  it('Outside renders hostile writers and targets as text', async () => {
    mockFetch({
      'GET /api/bypass': {
        body: [bypassRow({ user: EVIL, groups: [EVIL, EVIL], verb: EVIL, group: EVIL, resource: EVIL, subresource: EVIL, namespace: EVIL, name: EVIL, uid: EVIL })],
      },
    });
    const { container } = render(<Outside />);
    await waitFor(() => expect(screen.getAllByText(EVIL, { exact: false }).length).toBeGreaterThanOrEqual(3));
    clean(container);
  });

  it('Agents renders hostile agents, humans and states as text', async () => {
    mockFetch({
      'GET /api/sessions': { body: [session({ agent: EVIL, human: EVIL, state: EVIL as 'active', expires: new Date(Date.now() + 3_600_000).toISOString() })] },
    });
    const { container } = render(<Agents />);
    expect((await screen.findAllByText(EVIL)).length).toBeGreaterThanOrEqual(2);
    clean(container);
  });

  it('Policy shows a hostile parse error verbatim, as text', async () => {
    mockFetch({
      'GET /api/policy': { body: { source: EVIL, text: EVIL } },
      'POST /api/policy/replay': { status: 400, body: { error: EVIL } },
    });
    const { container } = render(<Policy />);
    await screen.findByLabelText('Loaded policy');
    await userEvent.click(screen.getByRole('button', { name: /^replay over the last/i }));
    const err = await screen.findByLabelText('Policy error');
    expect(err.textContent).toBe(EVIL);
    clean(container);
  });
});
