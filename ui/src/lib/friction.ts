// The friction ladder (spec §6): how much confirmation an approval needs.
// First match wins, in exactly the order below, so a new class can only
// ever raise friction by accident, never quietly lower it.
import type { ApprovalSummary, Impact } from '../api';

export type FrictionLevel = 'typed' | 'confirm-undo' | 'confirm';
export type Tone = 'danger' | 'caution' | 'ok';
export type Friction = { level: FrictionLevel; tag: string; tone: Tone; why: string; unknownImpact: boolean };

export const KNOWN_CLASSES: ReadonlySet<string> = new Set(['READ', 'REVERSIBLE', 'COMPENSABLE', 'TERMINAL', 'AUTHORITY']);

// ARM_MS: how long the confirm control waits before it can be pressed, so
// a reflex click right after the card appears can never count as a decision.
export const ARM_MS = 300;

// invalidCount: a destroyed-object count blastgate can't vouch for — the
// wrong type, NaN/Infinity, or negative — is worse than "nothing
// destroyed": something upstream already lied, so this reads as unknown
// too rather than as a calm zero.
function invalidCount(n: unknown): boolean {
  return typeof n !== 'number' || !Number.isFinite(n) || n < 0;
}

export function frictionOf(
  s: Pick<ApprovalSummary, 'class' | 'measured' | 'data_destroyed'>,
  impact?: Pick<Impact, 'measured' | 'dataDestroyed'>,
): Friction {
  // An empty/unknown class, an unmeasured hold (exec, proxy, a scoring
  // timeout), an impact whose own `measured` is not exactly `true`
  // (missing, or any other truthy-but-wrong value fails closed), or
  // either side's destroyed-count failing to parse as a real count: all
  // of these mean blastgate itself does not know the blast radius, so
  // this always wins over any tag below.
  const unknown =
    !KNOWN_CLASSES.has(s.class) ||
    s.measured !== true ||
    (impact !== undefined && impact.measured !== true) ||
    invalidCount(s.data_destroyed) ||
    (impact !== undefined && invalidCount(impact.dataDestroyed));
  if (unknown) {
    return {
      level: 'typed',
      tag: 'Impact unknown',
      tone: 'caution',
      why: "blastgate can't tell what this will change, so it needs your decision.",
      unknownImpact: true,
    };
  }
  if (s.data_destroyed > 0 || (impact?.dataDestroyed ?? 0) > 0) {
    return { level: 'typed', tag: 'Cannot be undone', tone: 'danger', why: 'Its data would be destroyed with it.', unknownImpact: false };
  }
  switch (s.class) {
    case 'TERMINAL':
      return { level: 'typed', tag: 'Cannot be undone', tone: 'danger', why: 'This cannot be taken back.', unknownImpact: false };
    case 'AUTHORITY':
      return {
        level: 'typed',
        tag: 'Grants access',
        tone: 'danger',
        why: 'This gives an account more access to the cluster.',
        unknownImpact: false,
      };
    case 'COMPENSABLE':
      return {
        level: 'confirm-undo',
        tag: 'Needs a follow-up to undo',
        tone: 'caution',
        why: 'Undoing this needs a follow-up change.',
        unknownImpact: false,
      };
    default:
      // REVERSIBLE and READ: the only two levels left after the switch.
      return { level: 'confirm', tag: 'Can be undone', tone: 'ok', why: 'This can be undone.', unknownImpact: false };
  }
}

// typedTarget: the string an approver must retype to arm a typed confirm.
// Never '' — an empty target could be satisfied by an empty paste.
export function typedTarget(s: Pick<ApprovalSummary, 'namespace' | 'name' | 'resource' | 'verb'>): string {
  return (s.namespace && s.name ? `${s.namespace}/${s.name}` : s.name) || s.resource || s.verb || 'approve';
}

// canSelfApprove: false only when the two names match exactly (trimmed,
// case-sensitive, as the server records them). The server does not
// enforce this itself — it is a UI-only guard (spec §6, §9) — so it
// fails open rather than lock someone out over a rendering quirk. An
// empty meName means /api/me has not answered yet, which only means the
// UI cannot tell who "self" is yet; that never blocks by itself. human
// may be missing from stored JSON; it then matches no one.
export function canSelfApprove(meName: string, human: string | undefined): boolean {
  const me = meName.trim();
  const h = (human ?? '').trim();
  return me === '' || me !== h;
}
