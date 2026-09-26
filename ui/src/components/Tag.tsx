import type { ReactNode } from 'react';
import type { Tone } from '../lib/friction';

// One glyph per tone, so a status never rides on colour alone (spec §7:
// colour, glyph and word). The shapes differ as well as the colours, for
// anyone who cannot tell red from amber from green.
export const GLYPH: Record<Tone, string> = { danger: '■', caution: '◆', ok: '●' };

export default function Tag({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={`tag tag-${tone}`}>
      <span className="tag-glyph" aria-hidden="true">
        {GLYPH[tone]}
      </span>
      <span>{children}</span>
    </span>
  );
}
