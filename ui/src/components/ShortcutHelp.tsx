import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react';
import Button from './Button';
import { hasModifier, isTyping } from '../hooks/useListKeys';

// join: "/" is either key, "+" is both together.
const SHORTCUTS: { keys: string[]; join?: '/' | '+'; what: string }[] = [
  { keys: ['j', 'k'], join: '/', what: 'Move down and up a list' },
  { keys: ['Enter'], what: 'Open the selected request' },
  { keys: ['Esc'], what: 'Go back, or close this' },
  { keys: ['⌘ or Ctrl', 'Enter'], join: '+', what: 'Approve after typing the name' },
  { keys: ['?'], what: 'Show these shortcuts' },
];

// ShortcutHelp lists the keyboard shortcuts when ? is pressed anywhere
// outside a text field. It is a modal on purpose: it is opened on demand,
// holds nothing to act on, and focus must come back to where the approver
// was the moment it closes.
export default function ShortcutHelp() {
  const [open, setOpen] = useState(false);
  const returnTo = useRef<HTMLElement | null>(null);
  const dialog = useRef<HTMLDivElement>(null);
  const close = useRef<HTMLButtonElement>(null);
  const titleId = useId();

  useEffect(() => {
    function onKey(e: globalThis.KeyboardEvent) {
      if (e.key !== '?' || e.defaultPrevented || hasModifier(e) || isTyping(e.target)) return;
      e.preventDefault();
      setOpen((was) => {
        if (!was) returnTo.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
        return true;
      });
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    if (open) close.current?.focus();
  }, [open]);

  function dismiss() {
    setOpen(false);
    // Back to the control that had focus, or the next Tab starts from the
    // top of the page and a keyboard user loses their place.
    const back = returnTo.current;
    returnTo.current = null;
    if (back?.isConnected) back.focus();
  }

  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      dismiss();
      return;
    }
    if (e.key !== 'Tab') return;
    // aria-modal only tells assistive tech; Tab still walks out into the
    // page behind unless it is kept in here.
    const focusables = Array.from(dialog.current?.querySelectorAll<HTMLElement>('button, [href], [tabindex]:not([tabindex="-1"])') ?? []);
    if (focusables.length === 0) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const at = document.activeElement;
    if (e.shiftKey && (at === first || !dialog.current?.contains(at))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (at === last || !dialog.current?.contains(at))) {
      e.preventDefault();
      first.focus();
    }
  }

  if (!open) return null;
  return (
    <div className="shortcut-backdrop" onMouseDown={(e) => e.target === e.currentTarget && dismiss()}>
      <div ref={dialog} className="shortcut-help" role="dialog" aria-modal="true" aria-labelledby={titleId} onKeyDown={onKeyDown}>
        <h2 id={titleId} className="shortcut-title">
          Keyboard shortcuts
        </h2>
        <dl className="shortcut-list">
          {SHORTCUTS.map(({ keys, join, what }) => (
            <div className="shortcut-row" key={what}>
              <dt className="shortcut-keys">
                {keys.map((k, i) => (
                  <span key={k}>
                    {i > 0 && <span className="shortcut-join">{join}</span>}
                    <kbd className="shortcut-key">{k}</kbd>
                  </span>
                ))}
              </dt>
              <dd className="shortcut-what">{what}</dd>
            </div>
          ))}
        </dl>
        <p className="shortcut-note">Letter keys do nothing while you are typing in a field.</p>
        <Button ref={close} className="shortcut-close" onClick={dismiss}>
          Close
        </Button>
      </div>
    </div>
  );
}
