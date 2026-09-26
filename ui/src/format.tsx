// Re-exports lib/format's pure helpers so the existing views keep working
// unchanged; Task 9 moves their imports over and retires this file.
export { useNow, duration, clock, plural } from './lib/format';

export function target(namespace: string, name: string) {
  return (
    <span className="target">
      {namespace && <span className="ns">{namespace}/</span>}
      <span className="name">{name || '—'}</span>
    </span>
  );
}
