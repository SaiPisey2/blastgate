// @ts-expect-error -- this package has no @types/node; Vitest runs on Node.
import { readFileSync } from 'node:fs';
import { useState } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render, renderHook, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from './App';
import Shell, { announce } from './components/Shell';
import ShortcutHelp from './components/ShortcutHelp';
import SignIn from './views/SignIn';
import { useListKeys } from './hooks/useListKeys';
import { useMediaQuery } from './hooks/useMediaQuery';
import { emit, setCSRF, type Me } from './api';
import type { Route } from './router';
import { mockFetch } from './test/fetch';
import { renderWithMotion } from './test/motion';
import { mediaListenerCount, setMedia } from './test/media';

// Read from disk (Vitest runs from ui/): it stubs CSS imports to empty
// strings, even ?raw.
const componentsCSS = readFileSync('src/styles/components.css', 'utf8');

const ME: Me = { name: 'bob', csrf: 'c' };
const EVIL = '<img src=x onerror=alert(1)>';

beforeEach(() => {
  window.location.hash = '#/waiting';
});
afterEach(() => {
  cleanup();
  setCSRF('');
  vi.useRealTimers();
});

function shell(route: Route, pending: number | null = null, onSignOut = () => {}) {
  return render(
    <Shell route={route} pending={pending} me={ME} onSignOut={onSignOut}>
      <p>page body</p>
    </Shell>,
  );
}

async function go(hash: string) {
  await act(async () => {
    window.location.hash = hash;
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  });
}

describe('Shell', () => {
  it('has the brand, the four plain tabs and the header controls', () => {
    shell({ name: 'waiting' });
    const header = screen.getByRole('banner');
    expect(within(header).getByRole('link', { name: 'blastgate' }).getAttribute('href')).toBe('#/waiting');
    const nav = within(header).getByRole('navigation', { name: 'Main' });
    const tabs = within(nav).getAllByRole('link');
    expect(tabs.map((a) => a.textContent)).toEqual(['Waiting', 'Activity', 'Agents', 'Policy']);
    expect(tabs.map((a) => a.getAttribute('href'))).toEqual(['#/waiting', '#/activity', '#/agents', '#/policy']);
    // The live status, the theme toggle, who is signed in, and Sign out.
    expect(within(header).getByRole('status').textContent).toMatch(/Connecting|Live|Reconnecting|Offline|Too many tabs/);
    expect(within(header).getByRole('button', { name: /^Theme:/ })).toBeTruthy();
    expect(within(header).getByText('bob')).toBeTruthy();
    expect(within(header).getByRole('button', { name: 'Sign out' })).toBeTruthy();
    expect(screen.getByRole('main').textContent).toBe('page body');
  });

  it('the waiting tab shows the pending count and hides it at 0', () => {
    const { rerender } = shell({ name: 'activity' }, 3);
    const waiting = () => within(screen.getByRole('navigation', { name: 'Main' })).getAllByRole('link')[0];
    expect(waiting().textContent).toContain('3');
    // The number is said once, in words, not read out as a bare "3".
    expect(screen.getByRole('link', { name: 'Waiting, 3 requests' })).toBeTruthy();

    rerender(
      <Shell route={{ name: 'activity' }} pending={1} me={ME} onSignOut={() => {}}>
        <p />
      </Shell>,
    );
    expect(screen.getByRole('link', { name: 'Waiting, 1 request' })).toBeTruthy();

    for (const n of [0, null]) {
      rerender(
        <Shell route={{ name: 'activity' }} pending={n} me={ME} onSignOut={() => {}}>
          <p />
        </Shell>,
      );
      expect(waiting().textContent).toBe('Waiting');
      expect(screen.getByRole('link', { name: 'Waiting' })).toBeTruthy();
    }
  });

  it('the active tab is marked current', () => {
    const cases: [Route, string | null][] = [
      [{ name: 'waiting' }, 'Waiting'],
      // Details belongs to Waiting, and outside changes to Activity.
      [{ name: 'approval', id: 'a'.repeat(32) }, 'Waiting'],
      [{ name: 'activity' }, 'Activity'],
      [{ name: 'outside' }, 'Activity'],
      [{ name: 'agents' }, 'Agents'],
      [{ name: 'policy' }, 'Policy'],
      [{ name: 'notfound' }, null],
    ];
    for (const [route, current] of cases) {
      shell(route);
      const nav = screen.getByRole('navigation', { name: 'Main' });
      const marked = within(nav)
        .getAllByRole('link')
        .filter((a) => a.getAttribute('aria-current') === 'page')
        .map((a) => a.textContent);
      expect(marked, route.name).toEqual(current ? [current] : []);
      cleanup();
    }
  });

  it('tabs wrap on narrow screens', () => {
    shell({ name: 'waiting' });
    const nav = screen.getByRole('navigation', { name: 'Main' });
    expect(nav.classList.contains('shell-tabs')).toBe(true);
    // Wraps rather than scrolls sideways: a scroll strip hides the tabs
    // people then never find. Real layout at 360px is checked in a browser.
    expect(componentsCSS).toMatch(/\.shell-tabs\s*\{[^}]*flex-wrap:\s*wrap/);
  });

  it('the current tab is underlined with a border, never a shadow', () => {
    // Spec §7: hairlines, not shadows. Every tab carries the 2px border so
    // the current one's text does not shift.
    expect(componentsCSS).toMatch(/\.shell-tab\s*\{[^}]*border-bottom:\s*2px solid transparent/);
    expect(componentsCSS).toMatch(/\.shell-tab\[aria-current="page"\]\s*\{[^}]*border-bottom-color:\s*var\(--text\)/);
    expect(componentsCSS).not.toMatch(/\.shell-[a-z-]+[^{]*\{[^}]*box-shadow/);
  });

  it('a long approver name keeps its full text in the title', () => {
    const long = 'approver-with-a-very-long-name-that-truncates';
    render(
      <Shell route={{ name: 'waiting' }} pending={0} me={{ name: long, csrf: 'c' }} onSignOut={() => {}}>
        <p />
      </Shell>,
    );
    expect(screen.getByText(long).getAttribute('title')).toBe(long);
  });

  it('sign out calls logout', async () => {
    const onSignOut = vi.fn();
    shell({ name: 'waiting' }, null, onSignOut);
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(onSignOut).toHaveBeenCalledTimes(1);
  });

  it('the approver name is text, never markup', () => {
    render(
      <Shell route={{ name: 'waiting' }} pending={0} me={{ name: EVIL, csrf: 'c' }} onSignOut={() => {}}>
        <p />
      </Shell>,
    );
    expect(screen.getByText(EVIL)).toBeTruthy();
    expect(document.querySelector('img')).toBeNull();
  });
});

describe('Announcer', () => {
  it('announce puts text in the alert region', async () => {
    shell({ name: 'waiting' });
    const region = document.getElementById('announcer')!;
    expect(region.getAttribute('role')).toBe('alert');
    expect(screen.getAllByRole('alert')).toEqual([region]);

    act(() => announce('2 new requests are waiting'));
    await waitFor(() => expect(region.textContent).toBe('2 new requests are waiting'));

    // The same words again must be said again: the region is emptied
    // first, so a screen reader sees a change.
    act(() => announce('2 new requests are waiting'));
    expect(region.textContent).toBe('');
    await waitFor(() => expect(region.textContent).toBe('2 new requests are waiting'));
  });

  it('a new shell does not repeat the last announcement', async () => {
    const first = shell({ name: 'waiting' });
    act(() => announce('1 new request is waiting'));
    await waitFor(() => expect(document.getElementById('announcer')!.textContent).toBe('1 new request is waiting'));
    // Sign out and back in: the shell unmounts and a new one mounts.
    first.unmount();
    shell({ name: 'waiting' });
    expect(document.getElementById('announcer')!.textContent).toBe('');
  });

  it('a refill pending at unmount never lands in the next shell', async () => {
    const first = shell({ name: 'waiting' });
    act(() => announce('late words'));
    first.unmount();
    shell({ name: 'waiting' });
    await new Promise((r) => setTimeout(r, 200));
    expect(document.getElementById('announcer')!.textContent).toBe('');
  });

  it('announce is plain text', async () => {
    shell({ name: 'waiting' });
    act(() => announce(EVIL));
    const region = document.getElementById('announcer')!;
    await waitFor(() => expect(region.textContent).toBe(EVIL));
    expect(region.querySelector('img')).toBeNull();
  });
});

describe('Auth', () => {
  it('shows sign in when there is no session', async () => {
    mockFetch({ 'GET /api/me': { status: 401, body: { error: 'unauthorized' } } });
    renderWithMotion(<App />);
    expect(await screen.findByRole('heading', { name: 'Sign in to blastgate' })).toBeTruthy();
    expect(screen.queryByRole('banner')).toBeNull();
  });

  it('a 401 anywhere returns to sign in and back to the same page', async () => {
    window.location.hash = '#/agents';
    let sessionsOK = false;
    const calls = mockFetch({
      'GET /api/me': { body: ME },
      'GET /api/approvals': { body: [] },
      'GET /api/sessions': () => (sessionsOK ? { body: [] } : { status: 401, body: { error: 'unauthorized' } }),
      'POST /api/login': () => {
        sessionsOK = true;
        return { body: { name: 'bob', csrf: 'c2' } };
      },
    });
    renderWithMotion(<App />);
    const field = (await screen.findByLabelText(/login token/i)) as HTMLInputElement;
    expect(window.location.hash).toBe('#/login');

    await userEvent.type(field, 'bga_again{Enter}');
    await waitFor(() => expect(window.location.hash).toBe('#/agents'));
    expect(await screen.findByRole('link', { name: 'Agents', current: 'page' })).toBeTruthy();
    expect(calls.filter((c) => c.url === '/api/login')).toHaveLength(1);
  });

  it('signing in from the sign-in page itself lands on Waiting', async () => {
    window.location.hash = '#/login';
    mockFetch({
      'GET /api/me': { status: 401, body: { error: 'unauthorized' } },
      'GET /api/approvals': { body: [] },
      'POST /api/login': { body: { name: 'bob', csrf: 'c2' } },
    });
    renderWithMotion(<App />);
    await userEvent.type(await screen.findByLabelText(/login token/i), 'bga_x{Enter}');
    await waitFor(() => expect(window.location.hash).toBe('#/waiting'));
    expect(await screen.findByRole('link', { name: 'Waiting', current: 'page' })).toBeTruthy();
  });

  it('the stream event wins over the initial pending fetch', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const calls = mockFetch({
      'GET /api/me': { body: ME },
      'GET /api/feed': { body: [] },
      'GET /api/approvals': async () => {
        await gate;
        return { body: [] };
      },
    });
    window.location.hash = '#/activity';
    renderWithMotion(<App />);
    await screen.findByText('bob');
    await waitFor(() => expect(calls.some((c) => c.url.startsWith('/api/approvals'))).toBe(true));
    act(() => emit('approvals', { count: 2, ids: ['a'.repeat(32), 'b'.repeat(32)] }));
    expect(screen.getByRole('link', { name: 'Waiting, 2 requests' })).toBeTruthy();
    // The slower fetch answers with an empty list: it must not undo the
    // count the stream already gave.
    await act(async () => release());
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.getByRole('link', { name: 'Waiting, 2 requests' })).toBeTruthy();
  });

  it('sign out posts logout and returns to sign in', async () => {
    const calls = mockFetch({
      'GET /api/me': { body: ME },
      'GET /api/approvals': { body: [] },
      'POST /api/logout': { body: {} },
    });
    setCSRF('c');
    renderWithMotion(<App />);
    await userEvent.click(await screen.findByRole('button', { name: 'Sign out' }));
    expect(await screen.findByRole('heading', { name: 'Sign in to blastgate' })).toBeTruthy();
    expect(calls.some((c) => c.method === 'POST' && c.url === '/api/logout')).toBe(true);
  });

  it('every route renders a screen, old hashes included', async () => {
    mockFetch({
      'GET /api/me': { body: ME },
      'GET /api/approvals?status=pending': { body: [] },
      'GET /api/feed': { body: [] },
      'GET /api/sessions': { body: [] },
      'GET /api/policy': { body: { source: 'built-in', text: 'rules: []' } },
      'GET /api/bypass': { body: [] },
    });
    renderWithMotion(<App />);
    await screen.findByText('bob');
    for (const [hash, tab, heading] of [
      ['#/agents', 'Agents', 'Agents'],
      ['#/sessions', 'Agents', 'Agents'],
      ['#/policy', 'Policy', 'Policy'],
      ['#/activity/outside', 'Activity', 'Changes outside blastgate'],
      ['#/bypass', 'Activity', 'Changes outside blastgate'],
    ]) {
      await go(hash);
      expect(await screen.findByRole('heading', { level: 1, name: heading }), hash).toBeTruthy();
      expect(screen.getByRole('link', { name: tab, current: 'page' }), hash).toBeTruthy();
    }
    await go('#/nope');
    expect(await screen.findByText('There is no such page.')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Go to Waiting' }).getAttribute('href')).toBe('#/waiting');
  });
});

describe('SignIn', () => {
  it('has the sign-in copy and one token field', () => {
    render(<SignIn onSignedIn={() => {}} />);
    expect(screen.getByRole('heading', { level: 1, name: 'Sign in to blastgate' })).toBeTruthy();
    expect(screen.getByText('Paste the token you were given.')).toBeTruthy();
    const field = screen.getByLabelText(/login token/i) as HTMLInputElement;
    expect(field.type).toBe('password');
    expect(field.getAttribute('autocomplete')).toBe('one-time-code');
    expect(screen.getByRole('button', { name: 'Sign in' }).getAttribute('type')).toBe('submit');
  });

  it('sign in clears the field and never stores the token', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const calls = mockFetch({ 'POST /api/login': { body: { name: 'bob', csrf: 'c1' } } });
    const onSignedIn = vi.fn();
    render(<SignIn onSignedIn={onSignedIn} />);
    const field = screen.getByLabelText(/login token/i) as HTMLInputElement;
    await userEvent.type(field, 'bga_secret-token');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(onSignedIn).toHaveBeenCalledWith({ name: 'bob', csrf: 'c1' }));
    expect(field.value).toBe('');
    expect(JSON.parse(calls[0].body!)).toEqual({ token: 'bga_secret-token' });
    expect(setItem).not.toHaveBeenCalled();
    expect(document.cookie).not.toContain('bga_');
  });

  it('a refused token gets one generic line, and is still cleared', async () => {
    mockFetch({ 'POST /api/login': { status: 401, body: { error: EVIL } } });
    render(<SignIn onSignedIn={() => {}} />);
    const field = screen.getByLabelText(/login token/i) as HTMLInputElement;
    await userEvent.type(field, 'bga_wrong{Enter}');
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toBe('That token was not accepted.');
    // The server's own words are never shown.
    expect(document.body.textContent).not.toContain('onerror');
    expect(field.value).toBe('');
  });

  it('says to wait when rate limited, and to retry when unreachable', async () => {
    mockFetch({ 'POST /api/login': { status: 429, body: { error: 'slow down' } } });
    render(<SignIn onSignedIn={() => {}} />);
    await userEvent.type(screen.getByLabelText(/login token/i), 'bga_x{Enter}');
    expect((await screen.findByRole('alert')).textContent).toBe('Too many attempts. Wait a minute and try again.');
    cleanup();

    mockFetch({ 'POST /api/login': { status: 502 } });
    render(<SignIn onSignedIn={() => {}} />);
    await userEvent.type(screen.getByLabelText(/login token/i), 'bga_x{Enter}');
    expect((await screen.findByRole('alert')).textContent).toBe('Could not reach blastgate. Try again.');
  });

  it('an empty field sends nothing', async () => {
    const calls = mockFetch({ 'POST /api/login': { body: ME } });
    render(<SignIn onSignedIn={() => {}} />);
    await userEvent.type(screen.getByLabelText(/login token/i), '   {Enter}');
    expect(calls).toHaveLength(0);
  });
});

function List({ count = 4, onOpen = () => {}, onEscape = () => {} }: { count?: number; onOpen?: (i: number) => void; onEscape?: () => void }) {
  const [index, setIndex] = useState(0);
  const keys = useListKeys({ count, index, onMove: setIndex, onOpen, onEscape });
  return (
    <>
      <input aria-label="outside" />
      <ul aria-label="Items" {...keys}>
        {Array.from({ length: count }, (_, i) => (
          <li key={i} aria-selected={i === index}>
            item {i}
          </li>
        ))}
        <li>
          <input aria-label="inside" />
          <span contentEditable suppressContentEditableWarning data-testid="editable">
            note
          </span>
        </li>
      </ul>
      <p data-testid="index">{index}</p>
    </>
  );
}

describe('Keyboard', () => {
  it('useListKeys moves with j and k only when the list has focus', async () => {
    render(<List />);
    const at = () => screen.getByTestId('index').textContent;
    const list = screen.getByRole('list', { name: 'Items' });
    expect(list.tabIndex).toBe(0);

    // Typing j in a field does nothing, outside the list or inside it.
    await userEvent.click(screen.getByLabelText('outside'));
    await userEvent.keyboard('jjj');
    expect(at()).toBe('0');
    await userEvent.click(screen.getByLabelText('inside'));
    await userEvent.keyboard('jj');
    expect(at()).toBe('0');
    expect((screen.getByLabelText('inside') as HTMLInputElement).value).toBe('jj');
    screen.getByTestId('editable').focus();
    await userEvent.keyboard('j');
    expect(at()).toBe('0');

    list.focus();
    await userEvent.keyboard('j');
    expect(at()).toBe('1');
    await userEvent.keyboard('{ArrowDown}');
    expect(at()).toBe('2');
    await userEvent.keyboard('k');
    expect(at()).toBe('1');
    await userEvent.keyboard('{ArrowUp}{ArrowUp}{ArrowUp}');
    expect(at()).toBe('0');
    await userEvent.keyboard('{End}');
    expect(at()).toBe('3');
    await userEvent.keyboard('jjj');
    expect(at()).toBe('3');
    await userEvent.keyboard('{Home}');
    expect(at()).toBe('0');
    // A modified letter belongs to the browser or the OS, not the list.
    await userEvent.keyboard('{Control>}j{/Control}{Meta>}j{/Meta}{Alt>}j{/Alt}');
    expect(at()).toBe('0');
  });

  it('useListKeys opens with Enter and leaves with Escape', async () => {
    const onOpen = vi.fn();
    const onEscape = vi.fn();
    render(<List onOpen={onOpen} onEscape={onEscape} />);
    const list = screen.getByRole('list', { name: 'Items' });
    list.focus();
    await userEvent.keyboard('j{Enter}');
    expect(onOpen).toHaveBeenCalledWith(1);
    await userEvent.keyboard('{Escape}');
    expect(onEscape).toHaveBeenCalledTimes(1);

    // Enter in the field inside the list is the field's own.
    await userEvent.click(screen.getByLabelText('inside'));
    await userEvent.keyboard('{Enter}');
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it('useListKeys does nothing on an empty list', () => {
    const onMove = vi.fn();
    const onOpen = vi.fn();
    const { result } = renderHook(() => useListKeys({ count: 0, index: -1, onMove, onOpen }));
    for (const key of ['j', 'k', 'ArrowDown', 'Home', 'End', 'Enter']) {
      const ev = new KeyboardEvent('keydown', { key });
      const target = document.createElement('ul');
      result.current.onKeyDown({ key, target, currentTarget: target, nativeEvent: ev, preventDefault: () => {} } as never);
    }
    expect(onMove).not.toHaveBeenCalled();
    expect(onOpen).not.toHaveBeenCalled();
  });

  it('? opens the shortcut help, Esc closes it and returns focus', async () => {
    render(
      <Shell route={{ name: 'waiting' }} pending={0} me={ME} onSignOut={() => {}}>
        <button type="button">somewhere</button>
        <input aria-label="note" />
        <textarea aria-label="long note" />
        <select aria-label="pick">
          <option>a</option>
        </select>
        <div contentEditable suppressContentEditableWarning data-testid="editable">
          text
        </div>
      </Shell>,
    );
    // Typing a question mark into a field is typing, not a shortcut.
    for (const el of [screen.getByLabelText('note'), screen.getByLabelText('long note'), screen.getByLabelText('pick'), screen.getByTestId('editable')]) {
      el.focus();
      await userEvent.keyboard('?');
      expect(screen.queryByRole('dialog'), el.tagName).toBeNull();
    }

    const trigger = screen.getByRole('button', { name: 'somewhere' });
    trigger.focus();
    await userEvent.keyboard('?');
    const dialog = screen.getByRole('dialog', { name: 'Keyboard shortcuts' });
    expect(dialog.getAttribute('aria-modal')).toBe('true');
    expect(dialog.contains(document.activeElement)).toBe(true);
    const text = dialog.textContent!;
    for (const want of ['j', 'k', 'Enter', 'Esc', '?']) expect(text).toContain(want);
    expect(text).toMatch(/approve after typing the name/i);
    expect(text).toMatch(/⌘|Ctrl/);

    // Tab stays inside the dialog while it is open.
    await userEvent.tab();
    expect(dialog.contains(document.activeElement)).toBe(true);
    await userEvent.tab({ shift: true });
    expect(dialog.contains(document.activeElement)).toBe(true);

    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  it('clicking the help text keeps focus in the dialog, so Esc still closes it', async () => {
    render(
      <>
        <button type="button">start</button>
        <ShortcutHelp />
      </>,
    );
    const start = screen.getByRole('button', { name: 'start' });
    start.focus();
    await userEvent.keyboard('?');
    const dialog = screen.getByRole('dialog');
    await userEvent.click(within(dialog).getByText('Move down and up a list'));
    expect(dialog.contains(document.activeElement)).toBe(true);
    await userEvent.tab();
    expect(dialog.contains(document.activeElement)).toBe(true);
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(start);
  });

  it('the shortcut help closes from its Close button too', async () => {
    render(
      <>
        <button type="button">start</button>
        <ShortcutHelp />
      </>,
    );
    const start = screen.getByRole('button', { name: 'start' });
    start.focus();
    await userEvent.keyboard('?');
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Close' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(start);
  });
});

describe('useMediaQuery', () => {
  it('follows the query and stops listening on unmount', () => {
    const q = '(min-width: 900px)';
    setMedia(q, true);
    const { result, unmount } = renderHook(() => useMediaQuery(q));
    expect(result.current).toBe(true);
    act(() => setMedia(q, false));
    expect(result.current).toBe(false);
    act(() => setMedia(q, true));
    expect(result.current).toBe(true);
    unmount();
    expect(mediaListenerCount(q)).toBe(0);
  });

  it('is false when the browser has no matchMedia', () => {
    const saved = window.matchMedia;
    // @ts-expect-error -- simulating a runtime without it
    delete window.matchMedia;
    try {
      const { result } = renderHook(() => useMediaQuery('(min-width: 1px)'));
      expect(result.current).toBe(false);
    } finally {
      window.matchMedia = saved;
    }
  });
});
