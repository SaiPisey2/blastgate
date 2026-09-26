import { useEffect, useState } from 'react';
import { onStreamStatus, streamStatus, type StreamStatus } from '../api';
import type { Tone } from '../lib/friction';

// Offline is danger, not neutral: a console that looks current while it
// is not is how an approver ends up deciding from a stale list.
const WORDS: Record<StreamStatus, [string, Tone]> = {
  connecting: ['Connecting', 'caution'],
  live: ['Live', 'ok'],
  reconnecting: ['Reconnecting', 'caution'],
  offline: ['Offline', 'danger'],
  limited: ['Too many tabs', 'caution'],
};

export default function LiveStatus() {
  const [status, setStatus] = useState<StreamStatus>(streamStatus);
  useEffect(() => {
    // Re-read on subscribe: the status may have moved between the first
    // render and this effect.
    setStatus(streamStatus());
    return onStreamStatus(setStatus);
  }, []);
  const [word, tone] = WORDS[status] ?? WORDS.offline;
  return (
    <span className={`live-status tone-${tone}`} role="status">
      <span className="live-status-dot" aria-hidden="true" />
      {word}
    </span>
  );
}
