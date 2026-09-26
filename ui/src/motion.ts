// The only door to Motion in this UI. Views import from here, never from
// 'motion/react', so the allow-list below is the whole surface they can
// reach.
//
// Why a list: the console runs under style-src 'self' with no nonce.
// AnimatePresence mode="popLayout" injects a <style> element to hold the
// exiting child's size, MotionConfig's nonce prop exists only to make that
// injection pass a CSP, and AnimateView drives view transitions through
// the same kind of injected styles. All of them are blocked at runtime by
// our CSP, so the bans are enforced here at compile time: the types below
// reject mode="popLayout" and nonce before a build could ship them.
import {
  AnimatePresence as MotionAnimatePresence,
  MotionConfig as MotionMotionConfig,
  type AnimatePresenceProps,
  type MotionConfigProps,
} from 'motion/react';
import type { JSX } from 'react';

export { m, LazyMotion, domAnimation, useReducedMotion } from 'motion/react';

export const AnimatePresence = MotionAnimatePresence as (
  props: Omit<AnimatePresenceProps, 'mode'> & { mode?: 'sync' | 'wait' },
) => JSX.Element;

export const MotionConfig = MotionMotionConfig as (
  props: Omit<MotionConfigProps, 'nonce'>,
) => JSX.Element;

// One ease for everything: an exponential ease-out, so motion starts fast
// from an already-visible state and settles, instead of easing in.
export const EASE = [0.16, 1, 0.3, 1] as const;

// Seconds, from spec §7: a new waiting request enters in 240ms, a decided
// card leaves in at most 200ms, a new Activity row tints for 110ms, a
// disclosure or tree opens in 180ms.
export const DUR = { enter: 0.24, exit: 0.2, tint: 0.11, disclose: 0.18 } as const;
