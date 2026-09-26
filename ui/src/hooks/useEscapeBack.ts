import { useEffect } from 'react';
import { navigate } from '../router';
import { hasModifier, isTyping } from './useListKeys';

// useEscapeBack makes Esc go back to the page this one was opened from
// (Details to Waiting, outside changes to Activity), as the shortcut list
// promises. It stands aside whenever Esc already means something closer:
// inside a text field or a select, while a modal dialog is open, or when
// another handler (the confirm step's cancel, the shortcut list's close)
// has claimed the key with preventDefault.
export function useEscapeBack(hash: string) {
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key !== 'Escape' || e.defaultPrevented || hasModifier(e) || e.shiftKey || isTyping(e.target)) return;
      if (document.querySelector('[role="dialog"][aria-modal="true"]')) return;
      e.preventDefault();
      navigate(hash);
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [hash]);
}
