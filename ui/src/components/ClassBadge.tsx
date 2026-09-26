// Severity drives colour: reads and reversible changes stay calm so the
// eye learns to skip them, compensable changes are amber, and anything
// that cannot be taken back (or grants power) is red. The class string
// comes from the API, so it picks a tone from a fixed map and is shown
// as text; it never becomes part of a class name itself.
const TONES: Record<string, string> = {
  READ: 'read',
  REVERSIBLE: 'calm',
  COMPENSABLE: 'warn',
  TERMINAL: 'danger',
  AUTHORITY: 'danger',
};

// Fails closed: a class not in the map (missing, empty, or one the engine
// adds later) is shown as danger, never as a calm or neutral default.
// Object.hasOwn, not TONES[cls]: a class named "constructor" must not find
// Object.prototype's.
export function classTone(cls: string): string {
  return Object.hasOwn(TONES, cls) ? TONES[cls] : 'danger';
}

// measured={false} marks a class the engine could not measure (an exec,
// a proxied request, a scoring timeout): it reads "TERMINAL · UNMEASURED"
// in the danger tone, whatever the class. Left out, the class alone.
export default function ClassBadge({ cls, measured }: { cls: string; measured?: boolean }) {
  const unmeasured = measured === false;
  const label = !cls ? 'UNMEASURED' : unmeasured ? `${cls} · UNMEASURED` : cls;
  return <span className={`badge badge-${unmeasured ? 'danger' : classTone(cls)}`}>{label}</span>;
}

// Allow is the common case and stays grey, so held and denied requests
// are what the eye lands on.
const DECISIONS: Record<string, string> = { allow: 'neutral', hold: 'warn', deny: 'danger' };

export function DecisionChip({ decision }: { decision: string }) {
  if (!decision) return <span className="dim">—</span>;
  return <span className={`chip chip-${DECISIONS[decision] ?? 'neutral'}`}>{decision}</span>;
}
