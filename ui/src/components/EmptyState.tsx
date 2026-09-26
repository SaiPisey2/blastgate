import type { ReactNode } from 'react';

export default function EmptyState({ title, sub }: { title: string; sub?: ReactNode }) {
  return (
    <div className="empty-state" role="status">
      <p className="empty-state-title">{title}</p>
      {sub && <p className="empty-state-sub">{sub}</p>}
    </div>
  );
}
