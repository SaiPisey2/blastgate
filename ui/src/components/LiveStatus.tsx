import { useEffect, useRef, useState } from 'react';
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

// SAID: the only moves worth interrupting for. The stream drops and comes
// back on its own (connecting, reconnecting, live), and saying each of
// those out loud was noise; losing updates, or being refused a stream for
// too many tabs, is what the approver has to know about.
const SAID: Record<string, string> = {
  offline: 'Offline: this page is not getting updates.',
  limited: 'Too many tabs: this page is not getting updates.',
};

export default function LiveStatus() {
  const [status, setStatus] = useState<StreamStatus>(streamStatus);
  const [said, setSaid] = useState('');
  const last = useRef<StreamStatus>(status);
  useEffect(() => {
    // Re-read on subscribe: the status may have moved between the first
    // render and this effect.
    setStatus(streamStatus());
    return onStreamStatus(setStatus);
  }, []);
  // Only a move into offline or limited is said; any other move clears the
  // region silently, so the next drop is heard again.
  useEffect(() => {
    if (last.current === status) return;
    last.current = status;
    setSaid(Object.hasOwn(SAID, status) ? SAID[status] : '');
  }, [status]);
  const [word, tone] = WORDS[status] ?? WORDS.offline;
  return (
    <span className={`live-status tone-${tone}`}>
      <span className="live-status-dot" aria-hidden="true" />
      {word}
      <span className="visually-hidden" role="status">
        {said}
      </span>
    </span>
  );
}
