import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Details from './Details';
import { setCSRF, type ApprovalDetail } from '../api';
import { mockFetch } from '../test/fetch';
import { renderWithMotion } from '../test/motion';
import { deploymentImpact, detail, ID1, impact, summary } from '../test/fixtures';

afterEach(() => {
  cleanup();
  setCSRF('');
});

const del = summary({ namespace: 'team-a', name: 'web', resource: 'deployments', verb: 'delete', data_destroyed: 1 });

function execDetail(): ApprovalDetail {
  const s = summary({ verb: 'create', resource: 'pods/exec', namespace: 'team-a', name: 'db-0', class: 'TERMINAL', data_destroyed: 0, summary: 'TERMINAL, 0 objects' });
  return {
    ...detail(s, impact({ effects: [], dataDestroyed: 0 })),
    action: {
      verb: 'create',
      resource: 'pods',
      subresource: 'exec',
      namespace: 'team-a',
      name: 'db-0',
      path: '/api/v1/namespaces/team-a/pods/db-0/exec',
      query: { command: ['psql', '-c', "drop table users; -- it's gone"], container: ['db'] },
    },
  };
}

// big finds one of the big numbers by its label.
function big(label: RegExp): HTMLElement {
  const numbers = screen.getByRole('list', { name: /in numbers/i });
  const el = within(numbers)
    .getAllByRole('listitem')
    .find((li) => label.test(li.querySelector('.big-number-label')?.textContent ?? ''));
  if (!el) throw new Error(`no big number for ${label}`);
  return el;
}

const value = (el: HTMLElement) => el.querySelector('.big-number-value')!.textContent;

describe('Details', () => {
  it('shows the big numbers from the impact', async () => {
    mockFetch({ [`GET /api/approvals/${ID1}`]: { body: detail(del, deploymentImpact()) } });
    renderWithMotion(<Details id={ID1} me="bob" />);
    await screen.findByRole('article');
    expect(value(big(/^volumes? destroyed$/))).toBe('1');
    expect(value(big(/^objects? affected$/))).toBe('7');
    expect(value(big(/^services? left with no backends$/))).toBe('1');
    expect(value(big(/^disruption budgets? broken$/))).toBe('1');
    expect(value(big(/^undo$/i))).toBe('None');
    // The tree is beside it, under its own heading.
    const affected = screen.getByRole('region', { name: 'What would be affected' });
    expect(within(affected).getByRole('tree')).toBeTruthy();
    // Already on the details page: no link to itself.
    expect(screen.queryByRole('link', { name: 'Show details' })).toBeNull();
  });

  it('data destroyed is shown in danger', async () => {
    mockFetch({ [`GET /api/approvals/${ID1}`]: { body: detail(del, deploymentImpact()) } });
    renderWithMotion(<Details id={ID1} me="bob" />);
    await screen.findByRole('article');
    expect(big(/^volumes? destroyed$/).classList.contains('tone-danger')).toBe(true);
    expect(big(/^objects? affected$/).classList.contains('tone-danger')).toBe(false);
    cleanup();

    const safe = summary({ class: 'REVERSIBLE', data_destroyed: 0 });
    mockFetch({ [`GET /api/approvals/${ID1}`]: { body: detail(safe, impact({ class: 'REVERSIBLE', dataDestroyed: 0 })) } });
    renderWithMotion(<Details id={ID1} me="bob" />);
    await screen.findByRole('article');
    expect(value(big(/^volumes? destroyed$/))).toBe('0');
    expect(big(/^volumes? destroyed$/).classList.contains('tone-danger')).toBe(false);
  });

  it('an unmeasured impact shows its numbers as unknown, not zero', async () => {
    const s = summary({ measured: false, data_destroyed: 0 });
    mockFetch({ [`GET /api/approvals/${ID1}`]: { body: detail(s, impact({ measured: false, dataDestroyed: 0, effects: [] })) } });
    renderWithMotion(<Details id={ID1} me="bob" />);
    await screen.findByRole('article');
    expect(value(big(/^volumes? destroyed$/))).toBe('Unknown');
    expect(value(big(/^objects? affected$/))).toBe('Unknown');
  });

  it('technical details show the action text', async () => {
    mockFetch({ [`GET /api/approvals/${ID1}`]: { body: execDetail() } });
    renderWithMotion(<Details id={ID1} me="bob" />);
    await screen.findByRole('article');
    const tech = screen.getByText('Technical details').closest('details')!;
    expect(tech.open).toBe(false);
    await userEvent.click(screen.getByText('Technical details'));
    expect(tech.open).toBe(true);
    const facts = within(tech);
    expect(facts.getByText('Verb').nextElementSibling!.textContent).toBe('create');
    expect(facts.getByText('Resource').nextElementSibling!.textContent).toBe('pods/exec');
    expect(facts.getByText('Namespace').nextElementSibling!.textContent).toBe('team-a');
    expect(facts.getByText('Name').nextElementSibling!.textContent).toBe('db-0');
    expect(facts.getByText('Rule').nextElementSibling!.textContent).toBe('hold-terminal');
    expect(facts.getByText('Approval id').nextElementSibling!.textContent).toBe(ID1);
    const action = facts.getByLabelText('Request action');
    expect(action.tagName).toBe('PRE');
    expect(action.textContent).toContain('/api/v1/namespaces/team-a/pods/db-0/exec');
    expect(action.textContent).toContain(`$ psql -c 'drop table users; -- it'\\''s gone'`);
  });

  it('an expired approval has no buttons', async () => {
    mockFetch({ [`GET /api/approvals/${ID1}`]: { body: detail({ ...del, status: 'expired' }, deploymentImpact()) } });
    renderWithMotion(<Details id={ID1} me="bob" />);
    const card = await screen.findByRole('article');
    expect(within(card).getByText('Expired.')).toBeTruthy();
    expect(within(card).queryByRole('button', { name: /^approve$/i })).toBeNull();
    expect(within(card).queryByRole('button', { name: /^deny$/i })).toBeNull();
  });

  it('a decided approval shows who decided', async () => {
    const d = { ...detail({ ...del, status: 'approved' }, deploymentImpact()), decided_by: 'carol', decided: '2026-09-26T10:00:00Z' };
    mockFetch({ [`GET /api/approvals/${ID1}`]: { body: d } });
    renderWithMotion(<Details id={ID1} me="bob" />);
    const card = await screen.findByRole('article');
    expect(within(card).getByText(/approved by carol/i)).toBeTruthy();
  });

  it('approving from the details page posts and shows the new state', async () => {
    let status = 'pending';
    const plain = summary({ class: 'REVERSIBLE', data_destroyed: 0, verb: 'patch', resource: 'deployments', name: 'web', namespace: 'team-a' });
    const calls = mockFetch({
      [`GET /api/approvals/${ID1}`]: () => ({
        body: { ...detail({ ...plain, status }, impact({ class: 'REVERSIBLE', dataDestroyed: 0, undo: 'objects' })), decided_by: status === 'pending' ? '' : 'bob' },
      }),
      [`POST /api/approvals/${ID1}/approve`]: () => {
        status = 'approved';
        return { body: {} };
      },
    });
    setCSRF('tok');
    renderWithMotion(<Details id={ID1} me="carol" />);
    const card = await screen.findByRole('article');
    await userEvent.click(within(card).getByRole('button', { name: /^approve$/i }));
    const confirm = within(card).getByRole('button', { name: /confirm approval/i }) as HTMLButtonElement;
    await waitFor(() => expect(confirm.disabled).toBe(false));
    await userEvent.click(confirm);
    expect(await screen.findByText(/approved by bob/i)).toBeTruthy();
    expect(calls.find((c) => c.method === 'POST')!.headers['x-blastgate-csrf']).toBe('tok');
  });

  it('an unknown id shows not found', async () => {
    mockFetch({});
    renderWithMotion(<Details id={ID1} me="bob" />);
    expect(await screen.findByText('There is no such request.')).toBeTruthy();
    expect(screen.getByRole('link', { name: /waiting/i }).getAttribute('href')).toBe('#/waiting');
    cleanup();

    // An id that is not one never reaches the API at all.
    const calls = mockFetch({});
    renderWithMotion(<Details id="../policy" me="bob" />);
    expect(await screen.findByText('There is no such request.')).toBeTruthy();
    expect(calls).toHaveLength(0);
  });

  it('a failed detail shows retry', async () => {
    let fail = true;
    mockFetch({
      [`GET /api/approvals/${ID1}`]: () => (fail ? { status: 500, body: { error: 'store unavailable' } } : { body: detail(del, deploymentImpact()) }),
    });
    renderWithMotion(<Details id={ID1} me="bob" />);
    expect(await screen.findByText(/store unavailable/)).toBeTruthy();
    expect(screen.queryByRole('article')).toBeNull();
    fail = false;
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('article')).toBeTruthy();
    expect(screen.queryByText(/store unavailable/)).toBeNull();
  });
});
