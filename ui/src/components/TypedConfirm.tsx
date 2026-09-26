import { useId, type ClipboardEvent, type DragEvent, type KeyboardEvent, type Ref } from 'react';

type Props = {
  expected: string;
  // Controlled: the owner holds the value, so it can clear it when the
  // request or its target changes and derive validity from the same
  // state it renders. A copy kept here could go stale the moment this
  // field unmounted and came back empty while the owner still said valid.
  value: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  autoFocus?: boolean;
  describedBy?: string;
  inputRef?: Ref<HTMLInputElement>;
  // labelId/hintId: let the owner point other controls (a disabled
  // Approve) at the words that explain what is still needed.
  labelId?: string;
  hintId?: string;
};

// block stops text arriving without being typed. Paste is the obvious
// way; dropping dragged text in is the same shortcut through another door.
const block = (e: ClipboardEvent | DragEvent) => e.preventDefault();

// TypedConfirm asks for the target to be typed out, character by
// character, before a hard-to-undo approval can go through. The point is
// reading the name while typing it, so anything that fills the field
// without typing (paste, drop, autofill, autocorrect) is refused.
export default function TypedConfirm({ expected, value, onChange, onSubmit, autoFocus, describedBy, inputRef, labelId, hintId }: Props) {
  const id = useId();
  const ownLabelId = useId();
  const ownHintId = useId();
  const lid = labelId ?? ownLabelId;
  const hid = hintId ?? ownHintId;
  // Exact match only: no trim, no case folding. "demo/Data" is not the
  // object being approved, and a near-miss must not pass.
  const valid = value === expected;

  function onKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    // isComposing: Enter that ends an IME composition is not a submit.
    if (e.key !== 'Enter' || e.nativeEvent.isComposing) return;
    e.preventDefault();
    // Only the chord submits (spec §6). A plain Enter is what a hand does
    // at the end of typing anything, so it must never be the approval.
    if (valid && (e.metaKey || e.ctrlKey)) onSubmit();
  }

  return (
    <div className="typed-confirm">
      <label id={lid} className="typed-confirm-label" htmlFor={id}>
        To approve, type <span className="mono">{expected}</span>
      </label>
      <input
        id={id}
        ref={inputRef}
        className="typed-confirm-input mono"
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={onKeyDown}
        onPaste={block}
        onDrop={block}
        autoFocus={autoFocus}
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
        spellCheck={false}
        aria-describedby={describedBy ? `${hid} ${describedBy}` : hid}
      />
      <span id={hid} className="typed-confirm-hint">
        ⌘/Ctrl+Enter to approve
      </span>
    </div>
  );
}
