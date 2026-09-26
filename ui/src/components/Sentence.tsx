// Sentence puts the identifier in mono inside describe()'s sentence.
// Plain lastIndexOf, no pattern: the name is untrusted text. describe
// always ends a named sentence with the name, or its literal fallback
// with namespace/name, so the last occurrence is the identifier and not
// a word that happens to contain it.
export default function Sentence({ sentence, target, name, identClass }: { sentence: string; target: string; name: string; identClass: string }) {
  const pick = target && sentence.lastIndexOf(target) >= 0 ? target : name && sentence.lastIndexOf(name) >= 0 ? name : '';
  if (!pick) return <>{sentence}</>;
  const i = sentence.lastIndexOf(pick);
  return (
    <>
      {sentence.slice(0, i)}
      <span className={`mono ${identClass}`}>{pick}</span>
      {sentence.slice(i + pick.length)}
    </>
  );
}
