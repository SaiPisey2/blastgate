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

export function classTone(cls: string): string {
  return TONES[cls] ?? 'neutral';
}

export default function ClassBadge({ cls }: { cls: string }) {
  return <span className={`badge badge-${classTone(cls)}`}>{cls || 'UNKNOWN'}</span>;
}

// Allow is the common case and stays grey, so held and denied requests
// are what the eye lands on.
const DECISIONS: Record<string, string> = { allow: 'neutral', hold: 'warn', deny: 'danger' };

export function DecisionChip({ decision }: { decision: string }) {
  if (!decision) return <span className="dim">—</span>;
  return <span className={`chip chip-${DECISIONS[decision] ?? 'neutral'}`}>{decision}</span>;
}
