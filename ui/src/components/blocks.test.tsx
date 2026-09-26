import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useState } from 'react';
import { act, cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Tag from './Tag';
import Button from './Button';
import Facts from './Facts';
import TypedConfirm from './TypedConfirm';
import EmptyState from './EmptyState';
import NewItemsPill from './NewItemsPill';
import LiveStatus from './LiveStatus';
import ThemeToggle from './ThemeToggle';
import { setStreamStatus, type StreamStatus } from '../api';

afterEach(() => {
  cleanup();
  act(() => setStreamStatus('offline'));
});

describe('Tag', () => {
  it('renders the glyph and the word for each tone', () => {
    for (const [tone, glyph] of [
      ['danger', '■'],
      ['caution', '◆'],
      ['ok', '●'],
    ] as const) {
      const { container } = render(<Tag tone={tone}>Some word</Tag>);
      const tag = container.firstElementChild!;
      expect(tag.className).toContain(`tag-${tone}`);
      expect(tag.textContent).toBe(`${glyph}Some word`);
      // The glyph repeats the colour for people who cannot see it; a
      // screen reader already has the word.
      expect(screen.getByText(glyph).getAttribute('aria-hidden')).toBe('true');
      cleanup();
    }
  });
});

describe('Button', () => {
  it('is a plain button of the given variant that never submits a form by accident', () => {
    render(
      <Button variant="danger" disabled>
        Approve
      </Button>,
    );
    const b = screen.getByRole('button', { name: 'Approve' }) as HTMLButtonElement;
    expect(b.type).toBe('button');
    expect(b.className).toContain('button-danger');
    expect(b.disabled).toBe(true);
    expect(b.getAttribute('aria-disabled')).toBe('true');
  });
});

describe('Facts', () => {
  it('lists label and value pairs, with a tone on the value', () => {
    render(<Facts items={[{ label: 'Asked by', value: 'alice' }, { label: 'What it affects', value: 'Unknown', tone: 'caution' }]} />);
    const list = screen.getByRole('list', { name: /facts/i });
    expect(list.querySelectorAll('li')).toHaveLength(2);
    expect(screen.getByText('Unknown').closest('.fact-value')!.className).toContain('tone-caution');
  });
});

describe('TypedConfirm', () => {
  // A controlled field needs an owner holding the value, as the panel does.
  function Owner({ onSubmit }: { onSubmit: () => void }) {
    const [value, setValue] = useState('');
    return <TypedConfirm expected="demo/data" value={value} onChange={setValue} onSubmit={onSubmit} />;
  }

  it('submits only on the chord with an exact match', async () => {
    const onSubmit = vi.fn();
    render(<Owner onSubmit={onSubmit} />);
    const field = screen.getByLabelText(/to approve, type/i) as HTMLInputElement;
    expect(screen.getByText('⌘/Ctrl+Enter to approve')).toBeTruthy();
    await userEvent.type(field, 'demo/DATA');
    await userEvent.keyboard('{Enter}{Meta>}{Enter}{/Meta}');
    expect(onSubmit).not.toHaveBeenCalled();
    await userEvent.clear(field);
    await userEvent.type(field, ' demo/data');
    await userEvent.keyboard('{Control>}{Enter}{/Control}');
    expect(onSubmit).not.toHaveBeenCalled();
    await userEvent.clear(field);
    await userEvent.type(field, 'demo/data');
    expect(field.value).toBe('demo/data');
    // A plain Enter never submits, even with the value right.
    await userEvent.keyboard('{Enter}');
    expect(onSubmit).not.toHaveBeenCalled();
    await userEvent.keyboard('{Meta>}{Enter}{/Meta}');
    await userEvent.keyboard('{Control>}{Enter}{/Control}');
    expect(onSubmit).toHaveBeenCalledTimes(2);
  });

  it('shows exactly the value its owner holds', () => {
    render(<TypedConfirm expected="demo/data" value="demo/da" onChange={() => {}} onSubmit={() => {}} />);
    expect((screen.getByLabelText(/to approve, type/i) as HTMLInputElement).value).toBe('demo/da');
  });
});

describe('EmptyState', () => {
  it('shows a title and an optional line under it', () => {
    render(<EmptyState title="Nothing is waiting for you." sub="Last decision 2 min ago" />);
    expect(screen.getByText('Nothing is waiting for you.')).toBeTruthy();
    expect(screen.getByText('Last decision 2 min ago')).toBeTruthy();
  });
});

describe('NewItemsPill', () => {
  it('renders nothing at 0', () => {
    const { container } = render(<NewItemsPill count={0} onShow={() => {}} />);
    expect(container.firstChild).toBeNull();
  });

  it('reads "↑ N new" and calls onShow', async () => {
    const onShow = vi.fn();
    render(<NewItemsPill count={3} onShow={onShow} />);
    const b = screen.getByRole('button', { name: /3 new/ });
    expect(b.textContent).toBe('↑ 3 new');
    await userEvent.click(b);
    expect(onShow).toHaveBeenCalledTimes(1);
  });
});

describe('LiveStatus', () => {
  it('follows the stream through all five states', () => {
    render(<LiveStatus />);
    const cases: [StreamStatus, string, string][] = [
      ['connecting', 'Connecting', 'caution'],
      ['live', 'Live', 'ok'],
      ['reconnecting', 'Reconnecting', 'caution'],
      ['offline', 'Offline', 'danger'],
      ['limited', 'Too many tabs', 'caution'],
    ];
    for (const [status, word, tone] of cases) {
      act(() => setStreamStatus(status));
      const el = screen.getByText(word).closest('.live-status')!;
      expect(el.className).toContain(`tone-${tone}`);
      expect(el.querySelector('.live-status-dot')!.getAttribute('aria-hidden')).toBe('true');
    }
  });

  it('starts from the current status, and stops listening when unmounted', () => {
    act(() => setStreamStatus('live'));
    const { unmount } = render(<LiveStatus />);
    expect(screen.getByText('Live')).toBeTruthy();
    unmount();
    expect(() => act(() => setStreamStatus('reconnecting'))).not.toThrow();
  });
});

describe('ThemeToggle', () => {
  beforeEach(() => {
    localStorage.clear();
    delete document.documentElement.dataset.theme;
  });
  afterEach(() => {
    localStorage.clear();
    delete document.documentElement.dataset.theme;
  });

  it('cycles System, Dark, Light and persists', async () => {
    render(<ThemeToggle />);
    const b = screen.getByRole('button', { name: 'Theme: System' });
    expect(document.documentElement.dataset.theme).toBeUndefined();
    await userEvent.click(b);
    expect(b.textContent).toBe('Theme: Dark');
    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(localStorage.getItem('blastgate-theme')).toBe('dark');
    await userEvent.click(b);
    expect(b.textContent).toBe('Theme: Light');
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(localStorage.getItem('blastgate-theme')).toBe('light');
    await userEvent.click(b);
    expect(b.textContent).toBe('Theme: System');
    // System hands control back to the CSS media query.
    expect(document.documentElement.dataset.theme).toBeUndefined();
    expect(localStorage.getItem('blastgate-theme')).toBe('system');
  });

  it('starts from the stored choice', () => {
    localStorage.setItem('blastgate-theme', 'light');
    render(<ThemeToggle />);
    expect(screen.getByRole('button').textContent).toBe('Theme: Light');
    expect(document.documentElement.dataset.theme).toBe('light');
  });

  it('survives throwing storage', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('SecurityError');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceededError');
    });
    render(<ThemeToggle />);
    const b = screen.getByRole('button');
    expect(b.textContent).toBe('Theme: System');
    await userEvent.click(b);
    expect(b.textContent).toBe('Theme: Dark');
    expect(document.documentElement.dataset.theme).toBe('dark');
  });
});
