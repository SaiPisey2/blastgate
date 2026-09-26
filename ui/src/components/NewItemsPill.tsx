// NewItemsPill offers new rows instead of pushing them in under the
// reader's eyes; nothing moves until they ask.
export default function NewItemsPill({ count, onShow }: { count: number; onShow: () => void }) {
  if (count <= 0) return null;
  return (
    <button type="button" className="new-pill" onClick={onShow}>
      <span aria-hidden="true">↑ </span>
      {count} new
    </button>
  );
}
