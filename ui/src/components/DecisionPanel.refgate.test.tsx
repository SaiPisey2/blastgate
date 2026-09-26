import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DecisionPanel, { type DecisionPanelProps } from './DecisionPanel';
import { mockFetch, type Call } from '../test/fetch';
import { renderWithMotion } from '../test/motion';
import { detail, ID1, impact, summary } from '../test/fixtures';

// The live-ref gate in decide(), on its own. Normally the exiting confirm
// step is inert (useIsPresent), so a click never reaches decide() at all.
// Here that layer is switched off through the project's own Motion door:
// the exiting Confirm stays enabled with the handler from its last live
// render, which is exactly the stale closure decide() must refuse.
vi.mock('../motion', async (orig) => ({ ...(await orig<typeof import('../motion')>()), useIsPresent: () => true }));

afterEach(cleanup);

const posts = (calls: Call[]) => calls.filter((c) => c.method === 'POST').map((c) => c.url);
const approveButton = () => screen.getByRole('button', { name: /^approve$/i }) as HTMLButtonElement;
const confirms = () => screen.queryAllByRole('button', { name: /confirm approval/i, hidden: true }) as HTMLButtonElement[];
const reversible = summary({ class: 'REVERSIBLE', data_destroyed: 0, verb: 'patch', resource: 'deployments', name: 'web' });
const revImpact = impact({ class: 'REVERSIBLE', dataDestroyed: 0, undo: 'objects', effects: [] });

describe('DecisionPanel live gate, with the inert exit switched off', () => {
  for (const [label, next] of [
    ['the detail is cleared', undefined],
    ['the detail becomes unmeasured (typed)', detail(reversible, { ...revImpact, measured: false })],
    ['the detail becomes data-destroying (typed)', detail(reversible, { ...revImpact, dataDestroyed: 2 })],
    ['the undo text changes', detail(reversible, { ...revImpact, undo: 'none' })],
    ['Cancel', 'cancel'],
  ] as const) {
    it(`a stale, still-enabled Confirm does nothing after ${label}`, async () => {
      const calls = mockFetch({ [`POST /api/approvals/${ID1}/approve`]: { body: {} } });
      const onDecided = vi.fn();
      const base: DecisionPanelProps = { me: 'bob', onRetry: vi.fn(), onDecided, summary: reversible, detail: detail(reversible, revImpact) };
      const { rerender } = renderWithMotion(<DecisionPanel {...base} />);
      await userEvent.click(approveButton());
      await waitFor(() => expect(confirms()[0].disabled).toBe(false));
      if (next === 'cancel') fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
      else rerender(<DecisionPanel {...base} detail={next} />);
      const c = confirms()[0];
      // Still mounted for its exit and still enabled: only the gate is left.
      expect(c).toBeTruthy();
      expect(c.disabled).toBe(false);
      fireEvent.click(c);
      await new Promise((r) => setTimeout(r, 30));
      expect(posts(calls)).toEqual([]);
      expect(onDecided).not.toHaveBeenCalled();
    });
  }
});
