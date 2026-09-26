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

export function frictionOf(
  s: Pick<ApprovalSummary, 'class' | 'measured' | 'data_destroyed'>,
  impact?: Pick<Impact, 'measured' | 'dataDestroyed'>,
): Friction {
  // An empty/unknown class or an unmeasured hold (exec, proxy, a scoring
  // timeout) means blastgate itself does not know the blast radius: the
  // approver has to decide blind, so this always wins over any tag below.
  const unknown = !KNOWN_CLASSES.has(s.class) || s.measured !== true || impact?.measured === false;
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
// case-sensitive, as the server records them). An empty meName means
// /api/me has not answered yet; that never blocks, because the server is
// the real authority and re-checks on submit regardless.
export function canSelfApprove(meName: string, human: string): boolean {
  return meName.trim() === '' || meName.trim() !== human.trim();
}
