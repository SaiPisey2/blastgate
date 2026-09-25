import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Queue from './Queue';
import { setCSRF } from '../api';
import { mockFetch } from '../test/fetch';
import { detail, ID1, ID2, impact, summary } from '../test/fixtures';

afterEach(() => {
  cleanup();
  setCSRF('');
});

const severe = summary();
const plain = summary({
  id: ID2,
  rule: 'hold-writes',
  verb: 'patch',
  resource: 'deployments',
  name: 'web',
  summary: 'REVERSIBLE, 1 object',
});

function routes() {
  return mockFetch({
    'GET /api/approvals?status=pending': { body: [severe, plain] },
    [`GET /api/approvals/${ID1}`]: { body: detail(severe, impact()) },
    [`GET /api/approvals/${ID2}`]: {
      body: detail(plain, impact({ class: 'REVERSIBLE', dataDestroyed: 0, undo: 'objects', effects: [{ kind: 'changed', object: 'apps/Deployment/demo/web' }] })),
    },
    'POST /api/approvals/': (c) => ({ body: { ...(c.url.includes(ID1) ? severe : plain), status: 'approved' } }),
  });
}

describe('Queue', () => {
  it('queue shows severity and requires typed confirm for data destruction', async () => {
    const calls = routes();
    setCSRF('tok');
    render(<Queue />);

    const severeCard = (await screen.findByText('data')).closest('article')!;
    const plainCard = screen.getByText('web').closest('article')!;
    await within(severeCard).findByText('TERMINAL');
    expect(severeCard.dataset.severity).toBe('severe');
    expect(plainCard.dataset.severity).toBe('calm');
    expect(within(severeCard).getByText(/1 volume with data destroyed/)).toBeTruthy();
    expect(within(severeCard).getByText('hold-terminal')).toBeTruthy();
    expect(await within(plainCard).findByText('REVERSIBLE')).toBeTruthy();

    // Destroying data: approving needs the namespace typed out.
    await userEvent.click(within(severeCard).getByRole('button', { name: /^approve/i }));
    const confirm = within(severeCard).getByRole('button', { name: /confirm approve/i }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    const typed = within(severeCard).getByLabelText(/type demo to approve/i);
    await userEvent.type(typed, 'dem');
    expect(confirm.disabled).toBe(true);
    await userEvent.type(typed, 'o');
    expect(confirm.disabled).toBe(false);
    await userEvent.click(confirm);
    await waitFor(() => expect(screen.queryByText('data')).toBeNull());
    const approve = calls.find((c) => c.method === 'POST')!;
    expect(approve.url).toBe(`/api/approvals/${ID1}/approve`);
    expect(approve.headers['x-blastgate-csrf']).toBe('tok');

    // A reversible change: a plain confirm, no typing.
    await userEvent.click(within(plainCard).getByRole('button', { name: /^deny/i }));
    expect(within(plainCard).queryByRole('textbox')).toBeNull();
    await userEvent.click(within(plainCard).getByRole('button', { name: /confirm deny/i }));
    await waitFor(() => expect(screen.queryByText('web')).toBeNull());
    expect(calls.filter((c) => c.method === 'POST').map((c) => c.url)).toEqual([
      `/api/approvals/${ID1}/approve`,
      `/api/approvals/${ID2}/deny`,
    ]);
    expect(await screen.findByText(/nothing is waiting/i)).toBeTruthy();
  });

  it('cancel backs out of the confirm step without deciding', async () => {
    const calls = routes();
    render(<Queue />);
    const card = (await screen.findByText('web')).closest('article')!;
    await within(card).findByText('REVERSIBLE');
    await userEvent.click(within(card).getByRole('button', { name: /^approve/i }));
    await userEvent.click(within(card).getByRole('button', { name: /cancel/i }));
    expect(within(card).getByRole('button', { name: /^approve/i })).toBeTruthy();
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });

  it('a decision made elsewhere removes the card with a note', async () => {
    mockFetch({
      'GET /api/approvals?status=pending': { body: [plain] },
      [`GET /api/approvals/${ID2}`]: { body: detail(plain, impact({ class: 'REVERSIBLE', dataDestroyed: 0 })) },
      'POST /api/approvals/': { status: 409, body: { error: 'not pending' } },
    });
    render(<Queue />);
    const card = (await screen.findByText('web')).closest('article')!;
    await within(card).findByText('REVERSIBLE');
    await userEvent.click(within(card).getByRole('button', { name: /^approve/i }));
    await userEvent.click(within(card).getByRole('button', { name: /confirm approve/i }));
    expect(await screen.findByText(/already decided/i)).toBeTruthy();
    expect(screen.queryByText('web')).toBeNull();
  });
});
