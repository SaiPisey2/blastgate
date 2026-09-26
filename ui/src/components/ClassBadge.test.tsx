import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import ClassBadge from './ClassBadge';

afterEach(cleanup);

describe('ClassBadge', () => {
  it('known classes get their own tone', () => {
    render(<ClassBadge cls="READ" />);
    render(<ClassBadge cls="COMPENSABLE" />);
    render(<ClassBadge cls="TERMINAL" />);
    expect(screen.getByText('READ').className).toContain('badge-read');
    expect(screen.getByText('COMPENSABLE').className).toContain('badge-warn');
    expect(screen.getByText('TERMINAL').className).toContain('badge-danger');
  });

  it('an unknown class gets the danger tone and shows its raw value', () => {
    render(<ClassBadge cls="SOMETHING_NEW" />);
    render(<ClassBadge cls="constructor" />);
    expect(screen.getByText('SOMETHING_NEW').className).toContain('badge-danger');
    expect(screen.getByText('constructor').className).toBe('badge badge-danger');
  });

  it('an empty class reads UNMEASURED, in the danger tone', () => {
    render(<ClassBadge cls="" />);
    expect(screen.getByText('UNMEASURED').className).toContain('badge-danger');
  });
});
