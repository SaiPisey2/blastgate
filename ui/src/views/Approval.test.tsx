import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Approval, { shellQuote } from './Approval';
import { setCSRF, type ApprovalDetail } from '../api';
import { mockFetch } from '../test/fetch';
import { deploymentImpact, detail, ID1, impact, summary } from '../test/fixtures';

afterEach(() => {
  cleanup();
  setCSRF('');
});

const del = summary({ namespace: 'team-a', name: 'web', resource: 'deployments', verb: 'delete', data_destroyed: 1 });

function execDetail(): ApprovalDetail {
  const s = summary({ verb: 'create', resource: 'pods', namespace: 'team-a', name: 'db-0', class: 'TERMINAL', data_destroyed: 0, summary: 'TERMINAL, 0 objects' });
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

describe('Approval', () => {
  it('shows the card header, the action and the impact tree', async () => {
    const d = { ...detail(del, deploymentImpact()), action: { verb: 'delete', path: '/apis/apps/v1/namespaces/team-a/deployments/web' } };
    mockFetch({ [`GET /api/approvals/${ID1}`]: { body: d } });
    const { container } = render(<Approval id={ID1} />);

    const card = (await screen.findByRole('article'))!;
    // The header is the queue's card: same severity, same badge.
    expect(card.dataset.severity).toBe('severe');
    expect(within(card).getByText('TERMINAL')).toBeTruthy();
    // Already on the details page: no link to itself.
    expect(within(card).queryByText('Details')).toBeNull();

    const action = screen.getByLabelText('Action');
    expect(action.tagName).toBe('PRE');
    expect(action.textContent).toContain('verb  delete');
    expect(action.textContent).toContain('path  /apis/apps/v1/namespaces/team-a/deployments/web');

    await waitFor(() => expect(container.querySelector('[data-object="apps/Deployment/team-a/web"]')).toBeTruthy());
  });

  it('an exec shows its command line', async () => {
    mockFetch({ [`GET /api/approvals/${ID1}`]: { body: execDetail() } });
    render(<Approval id={ID1} />);
    const action = await screen.findByLabelText('Action');
    expect(action.textContent).toContain('/api/v1/namespaces/team-a/pods/db-0/exec');
    expect(action.textContent).toContain(`$ psql -c 'drop table users; -- it'\\''s gone'`);
  });

  it('a decided approval shows who decided, not the buttons', async () => {
    const d = { ...detail({ ...del, status: 'approved' }, deploymentImpact()), decided_by: 'carol', decided: '2026-09-26T10:00:00Z' };
    mockFetch({ [`GET /api/approvals/${ID1}`]: { body: d } });
    render(<Approval id={ID1} />);
    const card = await screen.findByRole('article');
    expect(within(card).getByText(/approved by carol/i)).toBeTruthy();
    expect(within(card).queryByRole('button', { name: /approve/i })).toBeNull();
    expect(within(card).queryByRole('button', { name: /deny/i })).toBeNull();
  });

  it('approving from the details page posts and shows the new state', async () => {
    let status = 'pending';
    const plain = summary({ class: 'REVERSIBLE', data_destroyed: 0, verb: 'patch', resource: 'deployments', name: 'web', namespace: 'team-a' });
    const calls = mockFetch({
      [`GET /api/approvals/${ID1}`]: () => ({ body: { ...detail({ ...plain, status }, impact({ class: 'REVERSIBLE', dataDestroyed: 0, undo: 'objects' })), decided_by: status === 'pending' ? '' : 'bob' } }),
      [`POST /api/approvals/${ID1}/approve`]: () => {
        status = 'approved';
        return { body: {} };
      },
    });
    setCSRF('tok');
    render(<Approval id={ID1} />);
    const card = await screen.findByRole('article');
    await userEvent.click(within(card).getByRole('button', { name: /^approve/i }));
    const confirm = within(card).getByRole('button', { name: /confirm approve/i }) as HTMLButtonElement;
    await waitFor(() => expect(confirm.disabled).toBe(false));
    await userEvent.click(confirm);
    expect(await screen.findByText(/approved by bob/i)).toBeTruthy();
    expect(calls.find((c) => c.method === 'POST')!.headers['x-blastgate-csrf']).toBe('tok');
  });

  it('an unknown approval says so', async () => {
    mockFetch({});
    render(<Approval id={ID1} />);
    expect(await screen.findByText(/no approval with this id/i)).toBeTruthy();
  });

  it('quotes command arguments only when needed', () => {
    expect(shellQuote(['ls', '-la', '/var/lib'])).toBe('ls -la /var/lib');
    expect(shellQuote(['sh', '-c', 'echo hi'])).toBe("sh -c 'echo hi'");
    expect(shellQuote(['echo', ''])).toBe("echo ''");
    expect(shellQuote(["it's"])).toBe(`'it'\\''s'`);
  });
});
