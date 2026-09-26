import type { KeyboardEvent, KeyboardEventHandler } from 'react';

// isTyping reports whether a key press belongs to a text field. Letter
// shortcuts must never fire there (WCAG 2.1.4): an approver typing a
// name that contains a "j" would otherwise move the selection under
// their own hands.
export function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof Element)) return false;
  if (target.closest('input, textarea, select')) return true;
  // jsdom has no isContentEditable, and a browser's also covers inherited
  // editability; the attribute walk catches both.
  if (target instanceof HTMLElement && target.isContentEditable) return true;
  return target.closest('[contenteditable]:not([contenteditable="false"])') !== null;
}

// A modified key is the browser's or the OS's (Ctrl+K, Cmd+J), never the
// list's. Shift is left alone so ? and capital-letter layouts still work.
export function hasModifier(e: { ctrlKey: boolean; metaKey: boolean; altKey: boolean }): boolean {
  return e.ctrlKey || e.metaKey || e.altKey;
}

type Options = {
  count: number;
  index: number;
  onMove(i: number): void;
  onOpen?(i: number): void;
  onEscape?(): void;
};

// useListKeys gives a list j/k and the arrows to move, Home and End,
// Enter to open and Escape to leave. The handler goes on the list element
// itself, so keys only act while the list (or something in it) has focus;
// a document listener would steal j from every other screen. Moving never
// animates: selection by keyboard is instant (spec §7).
export function useListKeys({ count, index, onMove, onOpen, onEscape }: Options): { onKeyDown: KeyboardEventHandler; tabIndex: 0 } {
  function onKeyDown(e: KeyboardEvent) {
    if (hasModifier(e) || isTyping(e.target)) return;
    if (e.key === 'Escape') {
      if (!onEscape) return;
      e.preventDefault();
      onEscape();
      return;
    }
    if (count <= 0) return;
    const last = count - 1;
    // -1 means nothing is selected yet: any move starts at the top.
    const from = index < 0 || index > last ? -1 : index;
    let next: number | null = null;
    switch (e.key) {
      case 'j':
      case 'ArrowDown':
        next = from < 0 ? 0 : Math.min(from + 1, last);
        break;
      case 'k':
      case 'ArrowUp':
        next = from < 0 ? 0 : Math.max(from - 1, 0);
        break;
      case 'Home':
        next = 0;
        break;
      case 'End':
        next = last;
        break;
      case 'Enter':
        // Enter on a button or link inside the list is that control's own
        // activation; opening the row as well would do two things at once.
        if (e.target !== e.currentTarget && e.target instanceof Element && e.target.closest('button, a[href], summary')) return;
        if (from < 0 || !onOpen) return;
        e.preventDefault();
        onOpen(from);
        return;
      default:
        return;
    }
    // preventDefault even at an edge: the arrows would otherwise scroll
    // the page once the selection stops moving.
    e.preventDefault();
    if (next !== from) onMove(next);
  }
  return { onKeyDown, tabIndex: 0 };
}
