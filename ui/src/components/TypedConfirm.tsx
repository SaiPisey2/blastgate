import { useId, useState, type ClipboardEvent, type DragEvent, type KeyboardEvent, type Ref } from 'react';

type Props = {
  expected: string;
  onValid: (valid: boolean) => void;
  onSubmit: () => void;
  autoFocus?: boolean;
  describedBy?: string;
  inputRef?: Ref<HTMLInputElement>;
};

// block stops text arriving without being typed. Paste is the obvious
// way; dropping dragged text in is the same shortcut through another door.
const block = (e: ClipboardEvent | DragEvent) => e.preventDefault();

// TypedConfirm asks for the target to be typed out, character by
// character, before a hard-to-undo approval can go through. The point is
// reading the name while typing it, so anything that fills the field
// without typing (paste, drop, autofill, autocorrect) is refused.
export default function TypedConfirm({ expected, onValid, onSubmit, autoFocus, describedBy, inputRef }: Props) {
  const id = useId();
  const [value, setValue] = useState('');
  // Exact match only: no trim, no case folding. "demo/Data" is not the
  // object being approved, and a near-miss must not pass.
  const valid = value === expected;

  function onKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    // isComposing: Enter that ends an IME composition is not a submit.
    if (e.key !== 'Enter' || e.nativeEvent.isComposing) return;
    e.preventDefault();
    if (valid) onSubmit();
  }

  return (
    <div className="typed-confirm">
      <label className="typed-confirm-label" htmlFor={id}>
        To approve, type <span className="mono">{expected}</span>
      </label>
      <input
        id={id}
        ref={inputRef}
        className="typed-confirm-input mono"
        type="text"
        value={value}
        onChange={(e) => {
          setValue(e.target.value);
          onValid(e.target.value === expected);
        }}
        onKeyDown={onKeyDown}
        onPaste={block}
        onDrop={block}
        autoFocus={autoFocus}
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
        spellCheck={false}
        aria-describedby={describedBy}
      />
    </div>
  );
}
