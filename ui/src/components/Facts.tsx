import type { ReactNode } from 'react';
import type { Tone } from '../lib/friction';
import { GLYPH } from './Tag';

export type Fact = { label: string; value: ReactNode; tone?: Tone };

// Facts is the row of three under the question: a list, so a screen
// reader hears how many there are and can step through them.
export default function Facts({ items }: { items: Fact[] }) {
  return (
    <ul className="facts" aria-label="Facts">
      {items.map((f) => (
        <li key={f.label} className="fact">
          <span className="fact-label">{f.label}</span>
          <span className={`fact-value${f.tone ? ` tone-${f.tone}` : ''}`}>
            {f.tone && (
              <span className="fact-glyph" aria-hidden="true">
                {GLYPH[f.tone]}
              </span>
            )}
            <span>{f.value}</span>
          </span>
        </li>
      ))}
    </ul>
  );
}
