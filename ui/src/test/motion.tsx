import type { ReactNode } from 'react';
import { render, type RenderOptions } from '@testing-library/react';
import { LazyMotion, MotionConfig, domAnimation } from '../motion';

// MotionShell is main.tsx's wrapper, exactly. Without it Motion's
// features never load, exit animations finish at once, and a test cannot
// see what a real page does: an exiting element stays mounted, with its
// last props, for the length of its exit.
export function MotionShell({ children }: { children: ReactNode }) {
  return (
    <MotionConfig reducedMotion="user">
      <LazyMotion features={domAnimation} strict>
        {children}
      </LazyMotion>
    </MotionConfig>
  );
}

// renderWithMotion renders inside MotionShell; rerender keeps the wrapper.
export function renderWithMotion(ui: ReactNode, options?: Omit<RenderOptions, 'wrapper'>) {
  return render(ui, { ...options, wrapper: MotionShell });
}
