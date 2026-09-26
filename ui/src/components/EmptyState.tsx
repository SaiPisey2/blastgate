import type { ReactNode } from 'react';

// quiet: not a live region. Waiting passes it while its own note ("Denied.
// The agent was refused.") is being said: two status regions changing in
// the same moment talk over each other, and the note is the news.
export default function EmptyState({ title, sub, quiet }: { title: string; sub?: ReactNode; quiet?: boolean }) {
  return (
    <div className="empty-state" role={quiet ? undefined : 'status'}>
      <p className="empty-state-title">{title}</p>
      {sub && <p className="empty-state-sub">{sub}</p>}
    </div>
  );
}
