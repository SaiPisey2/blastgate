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
  class: 'REVERSIBLE',
  data_destroyed: 0,
});
const plainImpact = impact({ class: 'REVERSIBLE', dataDestroyed: 0, undo: 'objects', effects: [{ kind: 'changed', object: 'apps/Deployment/demo/web' }] });

function routes() {
  return mockFetch({
    'GET /api/approvals?status=pending': { body: [severe, plain] },
    [`GET /api/approvals/${ID1}`]: { body: detail(severe, impact()) },
    [`GET /api/approvals/${ID2}`]: { body: detail(plain, plainImpact) },
    'POST /api/approvals/': (c) => ({ body: { ...(c.url.includes(ID1) ? severe : plain), status: 'approved' } }),
  });
}

// The confirm button is inert for a moment after the confirm step opens.
async function armed(button: HTMLButtonElement) {
  await waitFor(() => expect(button.disabled).toBe(false));
}

// impactLoaded waits until a card shows its numbers (the detail arrived).
async function impactLoaded(card: HTMLElement) {
  await within(card).findByText(/^undo$/i);
}

describe('Queue', () => {
  it('queue shows severity and requires typed confirm for data destruction', async () => {
    const calls = routes();
    setCSRF('tok');
    render(<Queue />);

    const severeCard = (await screen.findByText('data')).closest('article')!;
    const plainCard = screen.getByText('web').closest('article')!;
    // Severity comes from the summary: right from the first paint.
    expect(severeCard.dataset.severity).toBe('severe');
    expect(plainCard.dataset.severity).toBe('calm');
    expect(within(severeCard).getByText('TERMINAL')).toBeTruthy();
    expect(within(plainCard).getByText('REVERSIBLE')).toBeTruthy();
    expect(within(severeCard).getByText(/1 volume with data destroyed/)).toBeTruthy();
    expect(within(severeCard).getByText('hold-terminal')).toBeTruthy();
    await impactLoaded(severeCard);

    // Destroying data: approving needs the namespace typed out.
    await userEvent.click(within(severeCard).getByRole('button', { name: /^approve/i }));
    const confirm = within(severeCard).getByRole('button', { name: /confirm approve/i }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    const typed = within(severeCard).getByLabelText(/type demo to approve/i);
    await userEvent.type(typed, 'dem');
    await new Promise((r) => setTimeout(r, 350));
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
    const deny = within(plainCard).getByRole('button', { name: /confirm deny/i }) as HTMLButtonElement;
    await armed(deny);
    await userEvent.click(deny);
    await waitFor(() => expect(screen.queryByText('web')).toBeNull());
    expect(calls.filter((c) => c.method === 'POST').map((c) => c.url)).toEqual([
      `/api/approvals/${ID1}/approve`,
      `/api/approvals/${ID2}/deny`,
    ]);
    expect(await screen.findByText(/nothing is waiting/i)).toBeTruthy();
  });

  it('a cluster-scoped deletecollection still needs typing', async () => {
    const all = summary({ verb: 'deletecollection', resource: 'persistentvolumes', namespace: '', name: '', data_destroyed: 3 });
    const calls = mockFetch({
      'GET /api/approvals?status=pending': { body: [all] },
      [`GET /api/approvals/${ID1}`]: { body: detail(all, impact({ dataDestroyed: 3 })) },
      'POST /api/approvals/': { body: all },
    });
    render(<Queue />);
    const card = (await screen.findAllByText('persistentvolumes'))[0].closest('article')!;
    await impactLoaded(card);
    await userEvent.click(within(card).getByRole('button', { name: /^approve/i }));
    const confirm = within(card).getByRole('button', { name: /confirm approve/i }) as HTMLButtonElement;
    await new Promise((r) => setTimeout(r, 350));
    expect(confirm.disabled).toBe(true);
    await userEvent.click(confirm);
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
    await userEvent.type(within(card).getByLabelText(/type persistentvolumes to approve/i), 'persistentvolumes');
    expect(confirm.disabled).toBe(false);
  });

  it('the summary alone decides that typing is required', async () => {
    // The detail disagrees (says nothing destroyed); the summary wins, so a
    // stale or partial detail can never switch the typed confirmation off.
    mockFetch({
      'GET /api/approvals?status=pending': { body: [severe] },
      [`GET /api/approvals/${ID1}`]: { body: detail(severe, impact({ dataDestroyed: 0 })) },
    });
    render(<Queue />);
    const card = (await screen.findByText('data')).closest('article')!;
    await impactLoaded(card);
    await userEvent.click(within(card).getByRole('button', { name: /^approve/i }));
    expect(within(card).getByLabelText(/type demo to approve/i)).toBeTruthy();
  });

  it('severity and typing do not wait for the detail; approve waits, with a retry on failure', async () => {
    let fail = true;
    mockFetch({
      'GET /api/approvals?status=pending': { body: [severe] },
      [`GET /api/approvals/${ID1}`]: () => (fail ? { status: 500, body: { error: 'store unavailable' } } : { body: detail(severe, impact()) }),
    });
    render(<Queue />);
    const card = (await screen.findByText('data')).closest('article')!;
    expect(card.dataset.severity).toBe('severe');
    expect(await within(card).findByText(/store unavailable/)).toBeTruthy();
    const approve = within(card).getByRole('button', { name: /^approve/i }) as HTMLButtonElement;
    expect(approve.disabled).toBe(true);

    fail = false;
    await userEvent.click(within(card).getByRole('button', { name: /retry/i }));
    await impactLoaded(card);
    expect(within(card).queryByText(/store unavailable/)).toBeNull();
    expect(approve.disabled).toBe(false);
    await userEvent.click(approve);
    expect(within(card).getByLabelText(/type demo to approve/i)).toBeTruthy();
  });

  it('a click right after opening the confirm step is ignored, and severe cards do not focus confirm', async () => {
    const calls = mockFetch({
      'GET /api/approvals?status=pending': { body: [summary({ class: 'TERMINAL', data_destroyed: 0 }), plain] },
      [`GET /api/approvals/${ID1}`]: { body: detail(severe, impact({ dataDestroyed: 0 })) },
      [`GET /api/approvals/${ID2}`]: { body: detail(plain, plainImpact) },
      'POST /api/approvals/': { body: plain },
    });
    render(<Queue />);
    const severeCard = (await screen.findByText('data')).closest('article')!;
    await impactLoaded(severeCard);
    await userEvent.click(within(severeCard).getByRole('button', { name: /^approve/i }));
    const confirm = within(severeCard).getByRole('button', { name: /confirm approve/i });
    // A double-click on Approve lands its second click here.
    await userEvent.click(confirm);
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
    // Once armed, the severe card's confirm still does not take focus.
    await armed(confirm as HTMLButtonElement);
    await new Promise((r) => setTimeout(r, 20));
    expect(document.activeElement).not.toBe(confirm);

    const plainCard = screen.getByText('web').closest('article')!;
    await impactLoaded(plainCard);
    await userEvent.click(within(plainCard).getByRole('button', { name: /^approve/i }));
    const plainConfirm = within(plainCard).getByRole('button', { name: /confirm approve/i });
    await waitFor(() => expect(document.activeElement).toBe(plainConfirm));
  });

  for (const cls of ['', 'SOMETHING_NEW']) {
    it(`an unknown class (${JSON.stringify(cls)}) fails closed: severe, no focus, typed confirm`, async () => {
      const s = summary({ class: cls, data_destroyed: 0, summary: 'not measured' });
      mockFetch({
        'GET /api/approvals?status=pending': { body: [s] },
        [`GET /api/approvals/${ID1}`]: { body: detail(s, impact({ class: cls, measured: false, dataDestroyed: 0 })) },
      });
      render(<Queue />);
      const card = (await screen.findByText('data')).closest('article')!;
      expect(card.dataset.severity).toBe('severe');
      await impactLoaded(card);
      await userEvent.click(within(card).getByRole('button', { name: /^approve/i }));
      const confirm = within(card).getByRole('button', { name: /confirm approve/i }) as HTMLButtonElement;
      const typed = within(card).getByLabelText(/type demo to approve/i);
      await new Promise((r) => setTimeout(r, 350));
      expect(confirm.disabled).toBe(true);
      expect(document.activeElement).not.toBe(confirm);
      await userEvent.type(typed, 'demo');
      expect(confirm.disabled).toBe(false);
    });
  }

  it('a READ card stays calm with a plain, focused confirm', async () => {
    const s = summary({ class: 'READ', data_destroyed: 0, verb: 'get', resource: 'secrets', summary: 'READ, 0 objects' });
    mockFetch({
      'GET /api/approvals?status=pending': { body: [s] },
      [`GET /api/approvals/${ID1}`]: { body: detail(s, impact({ class: 'READ', dataDestroyed: 0, effects: [] })) },
    });
    render(<Queue />);
    const card = (await screen.findByText('data')).closest('article')!;
    expect(card.dataset.severity).toBe('calm');
    await impactLoaded(card);
    await userEvent.click(within(card).getByRole('button', { name: /^approve/i }));
    expect(within(card).queryByRole('textbox')).toBeNull();
    const confirm = within(card).getByRole('button', { name: /confirm approve/i });
    await waitFor(() => expect(document.activeElement).toBe(confirm));
  });

  it('cancel backs out of the confirm step without deciding', async () => {
    const calls = routes();
    render(<Queue />);
    const card = (await screen.findByText('web')).closest('article')!;
    await impactLoaded(card);
    await userEvent.click(within(card).getByRole('button', { name: /^approve/i }));
    await userEvent.click(within(card).getByRole('button', { name: /cancel/i }));
    expect(within(card).getByRole('button', { name: /^approve/i })).toBeTruthy();
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
  });

  it('a decision made elsewhere removes the card with a note', async () => {
    mockFetch({
      'GET /api/approvals?status=pending': { body: [plain] },
      [`GET /api/approvals/${ID2}`]: { body: detail(plain, plainImpact) },
      'POST /api/approvals/': { status: 409, body: { error: 'not pending' } },
    });
    render(<Queue />);
    const card = (await screen.findByText('web')).closest('article')!;
    await impactLoaded(card);
    await userEvent.click(within(card).getByRole('button', { name: /^approve/i }));
    const confirm = within(card).getByRole('button', { name: /confirm approve/i }) as HTMLButtonElement;
    await armed(confirm);
    await userEvent.click(confirm);
    expect(await screen.findByText(/already decided/i)).toBeTruthy();
    expect(screen.queryByText('web')).toBeNull();
  });
});
