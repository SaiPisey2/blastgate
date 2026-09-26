import { useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { ApiError, post, type ApprovalDetail, type ApprovalSummary, type Impact } from '../api';
import { ARM_MS, canSelfApprove, frictionOf, typedTarget } from '../lib/friction';
import { describe } from '../lib/describe';
import { actionText, ago, clock, plural, useNow } from '../lib/format';
import { AnimatePresence, DUR, EASE, m, useIsPresent, useReducedMotion } from '../motion';
import Button from './Button';
import Facts, { type Fact } from './Facts';
import Tag from './Tag';
import TypedConfirm from './TypedConfirm';

export type Outcome = 'approved' | 'denied' | 'gone';

export type DecisionPanelProps = {
  summary: ApprovalSummary;
  detail?: ApprovalDetail;
  detailError?: string;
  // me: the signed-in approver's name, for the self-approval guard.
  me: string;
  onRetry: () => void;
  onDecided: (id: string, outcome: Outcome) => void;
  // position: set in the one-at-a-time layout ("1 of 3 waiting for you").
  position?: { index: number; total: number };
  // standalone: the panel heads its own details page, so no link to itself.
  standalone?: boolean;
  // body: shown in place of the three facts, between the why and the
  // controls. The details page puts its big numbers and the command here
  // (spec 4.2), so what approving would do is read before the buttons,
  // and says it once rather than as facts and again as numbers. A body
  // carries the command itself, so the panel drops "Show the command".
  body?: ReactNode;
};

export const SELF_APPROVAL_REASON = "You can't approve a request made on your behalf";
export const GONE_TEXT = 'This request is no longer waiting.';

const DONE_TEXT: Record<Exclude<Outcome, 'gone'>, string> = {
  approved: 'Approved. The agent can go ahead.',
  denied: 'Denied. The agent was refused.',
};

// The status comes from the API, so it picks words from a fixed map or is
// shown raw.
const STATUS: Record<string, string> = {
  approved: 'Approved',
  denied: 'Denied',
  consumed: 'Approved and carried out',
  expired: 'This request expired',
  superseded: 'Superseded',
};

// Nobody decides an expiry: "expired by bob" would name someone who did
// nothing, so an expired request only says when.
const NO_DECIDER = new Set(['expired']);

function decidedText(status: string, by: string, at: string): string {
  // Object.hasOwn, not `in`: a status of "toString" must not read a
  // function off the prototype.
  let t = Object.hasOwn(STATUS, status) ? STATUS[status] : status || 'Not pending';
  if (by && !NO_DECIDER.has(status)) t += ` by ${by}`;
  if (at && !Number.isNaN(Date.parse(at))) t += ` at ${clock(at)}`;
  return t + '.';
}

export function undoLabel(undo: unknown): string {
  const u = typeof undo === 'string' ? undo : '';
  switch (u) {
    case 'objects':
      return 'Snapshot kept';
    case 'none':
      return 'None';
    case '':
      return 'Unknown';
  }
  return u;
}

// affects is the count summary for "What it affects". Only reached for a
// measured impact: an unmeasured one reads Unknown, never a count, since
// its zeros mean "not looked at", not "nothing".
function affects(i: Impact): string {
  const n = i.effects?.length ?? 0;
  const parts = [`${n} ${plural(n, 'object')}`];
  if (i.dataDestroyed > 0) parts.push(`${i.dataDestroyed} ${plural(i.dataDestroyed, 'volume')} destroyed`);
  const emptied = Object.values(i.endpointsLeft ?? {}).filter((v) => v === 0).length;
  if (emptied > 0) parts.push(`${emptied} ${plural(emptied, 'service')} left with no backends`);
  const pdbs = i.pdbViolations?.length ?? 0;
  if (pdbs > 0) parts.push(`${pdbs} disruption ${plural(pdbs, 'budget')} broken`);
  return parts.join(', ');
}

// questionParts splits the plain sentence around its identifier, so the
// identifier can be set in mono and the words around it lowercased. Only
// the words are lowercased: an object name is shown exactly as it is.
// describe() ends every named sentence with the name (and its literal
// fallback with namespace/name), so a suffix check finds it; plain string
// comparison, never a pattern, because the name is untrusted.
function questionParts(sentence: string, target: string, name: string): { words: string; ident: string } {
  let words = sentence;
  let ident = '';
  if (target && sentence.endsWith(target)) {
    words = sentence.slice(0, sentence.length - target.length);
    ident = target;
  } else if (name && sentence.endsWith(name)) {
    // Show the full namespace/name, not the bare name: the approver must
    // see which namespace this lands in, and it is what they will type.
    words = sentence.slice(0, sentence.length - name.length);
    ident = target || name;
  } else if (target) {
    // Never hide the target, even from a sentence shaped differently.
    words = `${sentence} `;
    ident = target;
  }
  if (words) words = words.charAt(0).toLowerCase() + words.slice(1);
  return { words, ident };
}

// Keyed by id: nothing typed, armed or half-confirmed for one request may
// ever carry over to the next one shown in the same place.
export default function DecisionPanel(props: DecisionPanelProps) {
  return <Panel key={props.summary.id} {...props} />;
}

function Panel({ summary: s, detail: rawDetail, detailError, me, onRetry, onDecided, position, standalone, body }: DecisionPanelProps) {
  const now = useNow();
  // Height is not a transform, so MotionConfig's reducedMotion leaves it
  // animating; asking the OS for less motion gets an instant step here.
  const reduceMotion = useReducedMotion();
  const qid = useId();
  const reasonId = useId();
  const typedLabelId = useId();
  const typedHintId = useId();
  const detailErrorId = useId();
  const commandId = useId();
  const rootRef = useRef<HTMLElement>(null);
  const denyRef = useRef<HTMLButtonElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const approveRef = useRef<HTMLButtonElement>(null);
  const inFlight = useRef(false);

  const [typed, setTyped] = useState('');
  const [confirming, setConfirming] = useState(false);
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<Outcome | null>(null);
  const [showCommand, setShowCommand] = useState(false);

  // A detail for some other request (a late answer after the selection
  // moved) is no detail at all: it must never enable Approve here.
  const detail = rawDetail && rawDetail.id === s.id ? rawDetail : undefined;
  const impact = detail?.impact;
  const friction = frictionOf(s, impact);
  const needsTyping = friction.level === 'typed';
  const expected = typedTarget(s);
  const described = describe({ verb: s.verb, resource: s.resource, namespace: s.namespace, name: s.name });
  const { words, ident } = questionParts(described.sentence, described.target, s.name);
  const pending = s.status === 'pending';
  const selfBlocked = !canSelfApprove(me, s.human);

  // open: Approve can be pressed at all. ready: this press may send.
  // Both are computed here and checked again inside decide(), so no path
  // (a click, Enter, a chord, a stale closure) can approve around them.
  const decidable = pending && detail !== undefined && !selfBlocked && result === null;

  // Everything that armed or half-confirmed an approval is thrown away the
  // moment what it confirmed changes: the ladder level, the target to
  // type, or whether this request can be decided at all (a detail
  // refetch clears it for a moment). Done during render, not in an
  // effect, so no frame ever renders the stale state as ready.
  // Without this, a detail flap (typed -> confirm -> typed) remounted the
  // typed field empty while an earlier match still counted, and an armed
  // confirm step came back armed without waiting ARM_MS again.
  const typedKey = `${friction.level}\u0000${expected}`;
  const [seenTypedKey, setSeenTypedKey] = useState(typedKey);
  if (seenTypedKey !== typedKey) {
    setSeenTypedKey(typedKey);
    setTyped('');
  }
  // The impact's identity is part of it too: a same-level refetch whose
  // undo text or counts changed closes the step, so what the approver
  // confirms is always what they last read.
  // Keyed on the strings the panel renders, not on hand-picked fields: a
  // field left out here (services emptied, budgets broken) once let a
  // changed fact slip past an armed step.
  const impactKey = impact ? [affects(impact), undoLabel(impact.undo), impact.measured].join('\u0000') : '';
  const stepKey = `${friction.level}\u0000${decidable}\u0000${impactKey}`;
  const [seenStepKey, setSeenStepKey] = useState(stepKey);
  if (seenStepKey !== stepKey) {
    setSeenStepKey(stepKey);
    setConfirming(false);
    setArmed(false);
  }

  // typedOK is derived from the value on screen, never stored: it cannot
  // disagree with what the field shows.
  const typedOK = needsTyping && typed === expected;
  const open = decidable && !busy;
  const ready = open && (needsTyping ? typedOK : confirming && armed);
  // Not tied to busy: the step stays put while its request is in flight
  // rather than collapsing and reopening around a failed POST.
  const stepOpen = decidable && confirming && !needsTyping;

  // live: the gate as of the latest render. decide() reads it, never its
  // own closure: an element React or Motion keeps around after this panel
  // re-rendered (the confirm step during its exit animation) still holds
  // the handler from the render in which it was ready.
  const live = useRef({ pending, result, needsTyping, stepOpen, ready });
  live.current = { pending, result, needsTyping, stepOpen, ready };

  // When the step closes with focus inside it (Cancel, Escape, a refetch
  // flap), the exiting step goes inert and the browser would drop focus
  // to <body>. Hand it to the nearest harmless control instead: the typed
  // field if typing is now required, else Approve if it can take focus,
  // else the panel itself. Never Deny, for the reason given at cancel().
  // A layout effect, so focus moves before the inert step blurs.
  const wasOpen = useRef(stepOpen);
  useLayoutEffect(() => {
    const closed = wasOpen.current && !stepOpen;
    wasOpen.current = stepOpen;
    if (!closed) return;
    const a = document.activeElement;
    if (!(a instanceof HTMLElement) || !a.closest('.confirm-step-wrap') || !rootRef.current?.contains(a)) return;
    const target = needsTyping ? inputRef.current : approveRef.current && !approveRef.current.disabled ? approveRef.current : rootRef.current;
    target?.focus();
  }, [stepOpen, needsTyping]);

  // Arming restarts every time the step opens, whatever closed it.
  useEffect(() => {
    setArmed(false);
    if (!stepOpen) return;
    const t = setTimeout(() => setArmed(true), ARM_MS);
    return () => clearTimeout(t);
  }, [stepOpen]);

  // Default focus: the typed field when typing is required, otherwise
  // Deny, and never Approve. It only takes focus the page is not using
  // elsewhere (nothing focused, or already inside this panel), so a list
  // the approver is moving through with the keyboard keeps its focus.
  useEffect(() => {
    if (!pending) return;
    const active = document.activeElement;
    if (active && active !== document.body && !rootRef.current?.contains(active)) return;
    (needsTyping ? inputRef.current : denyRef.current)?.focus();
  }, [needsTyping, pending]);

  // Focus is never moved onto Confirm when it arms. It stays on Approve,
  // where a held Enter's key-repeat only reopens the step it already
  // opened; on Confirm the same repeat would approve (spec §6: no
  // single-key approve).

  // via: where an approval came from. A step click counts only while the
  // step is really open at this level; a typed submit only while typing
  // is what the ladder asks for now.
  async function decide(action: 'approve' | 'deny', via?: 'step' | 'typed') {
    const g = live.current;
    // inFlight, not only busy: two key events in one tick both see the
    // busy of the last render, and only one of them may send.
    if (!g.pending || inFlight.current || g.result !== null) return;
    if (action === 'approve') {
      if (!g.ready) return;
      if (via === 'step' && (g.needsTyping || !g.stepOpen)) return;
      if (via === 'typed' && !g.needsTyping) return;
    }
    inFlight.current = true;
    setBusy(true);
    setError('');
    try {
      await post(`/api/approvals/${encodeURIComponent(s.id)}/${action}`);
      const outcome = action === 'approve' ? 'approved' : 'denied';
      live.current.result = outcome;
      setResult(outcome);
      onDecided(s.id, outcome);
    } catch (e) {
      // 409: someone else decided it, or it expired, while this was open.
      // 404: it no longer exists. Either way it is not ours to decide.
      if (e instanceof ApiError && (e.status === 409 || e.status === 404)) {
        live.current.result = 'gone';
        setResult('gone');
        onDecided(s.id, 'gone');
        return;
      }
      setError(e instanceof Error ? e.message : 'The decision did not go through.');
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }

  // Cancel only closes the step; the layout effect below moves focus to
  // Approve. Never to Deny: a held Enter on Cancel would key-repeat into
  // a deny, a single-key decision (spec §6). On Approve the same repeat
  // only reopens a step that has to arm again.
  function cancel() {
    setConfirming(false);
  }

  const facts: Fact[] = [
    {
      label: 'Asked by',
      value: (
        <>
          {s.human || 'Unknown'}
          <span className="fact-aside"> · {ago(Number.isNaN(Date.parse(s.created)) ? s.age_seconds : (now - Date.parse(s.created)) / 1000)}</span>
        </>
      ),
    },
    friction.unknownImpact
      ? { label: 'What it affects', value: 'Unknown', tone: 'caution' }
      : impact
        ? { label: 'What it affects', value: affects(impact), tone: impact.dataDestroyed > 0 ? 'danger' : undefined }
        : { label: 'What it affects', value: s.summary || 'Unknown' },
    { label: 'Undo', value: impact ? undoLabel(impact.undo) : detailError ? 'Unknown' : 'Loading' },
  ];

  // Every reason Approve is disabled is tied to it by aria-describedby,
  // so a screen reader hears why, not just "dimmed".
  let reason = '';
  if (pending && result === null) {
    if (selfBlocked) reason = SELF_APPROVAL_REASON;
    else if (!detail && !detailError) reason = 'Approve is available once blastgate has loaded what this would change.';
  }
  const approveDescribedBy = [
    reason ? reasonId : '',
    detailError && !detail ? detailErrorId : '',
    needsTyping && !typedOK ? `${typedLabelId} ${typedHintId}` : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    // tabIndex -1: the panel can hold focus as a last resort when a
    // closing step leaves nothing else harmless to focus.
    <article ref={rootRef} className="decision" aria-labelledby={qid} data-level={friction.level} tabIndex={-1}>
      {position && (
        <p className="decision-position">
          {position.index} of {position.total} waiting for you
        </p>
      )}
      <Tag tone={friction.tone}>{friction.tag}</Tag>
      {/* tabIndex -1: after a decision, or on Enter from the list, focus
          lands here so the next thing read is the question. Not a tab
          stop, since it is not a control. */}
      <h2 id={qid} className={position ? 'decision-q decision-q-lg' : 'decision-q'} tabIndex={-1}>
        {s.agent || 'An agent'} wants to {words}
        {ident && <span className="mono">{ident}</span>}
      </h2>
      <p className="decision-why">{friction.why}</p>
      {body ?? <Facts items={facts} />}

      {detailError && !detail && (
        <div className="decision-detail-error" role="alert">
          <span id={detailErrorId}>Couldn't load what this would change: {detailError}</span>
          <Button variant="quiet" onClick={onRetry}>
            Retry
          </Button>
        </div>
      )}

      {error && (
        <p className="decision-error" role="alert">
          {error}
        </p>
      )}

      {!pending ? (
        // Only a pending approval can be decided; buttons on any other
        // would only ever produce a 409.
        <p className="decision-done" role="status">
          {decidedText(s.status, detail?.decided_by ?? '', detail?.decided ?? '')}
        </p>
      ) : result !== null ? (
        <p className="decision-done" role="status">
          {result === 'gone' ? GONE_TEXT : DONE_TEXT[result]}
        </p>
      ) : (
        <div className="decision-controls">
          {needsTyping && (
            <TypedConfirm
              expected={expected}
              value={typed}
              onChange={setTyped}
              onSubmit={() => void decide('approve', 'typed')}
              inputRef={inputRef}
              labelId={typedLabelId}
              hintId={typedHintId}
            />
          )}
          <div className="decision-buttons">
            <Button ref={denyRef} onClick={() => void decide('deny')} disabled={busy}>
              Deny
            </Button>
            <Button
              ref={approveRef}
              variant={needsTyping ? 'danger' : 'default'}
              disabled={needsTyping ? !ready : !open}
              aria-describedby={approveDescribedBy || undefined}
              aria-expanded={needsTyping ? undefined : stepOpen}
              onClick={() => {
                if (needsTyping) void decide('approve', 'typed');
                else if (open) setConfirming(true);
              }}
            >
              Approve
            </Button>
          </div>
          {reason && (
            <p id={reasonId} className="decision-reason">
              {reason}
            </p>
          )}
        </div>
      )}

      <AnimatePresence initial={false}>
        {stepOpen && (
          <ConfirmStep
            key="confirm"
            undo={friction.level === 'confirm-undo' && impact ? undoLabel(impact.undo) : undefined}
            ready={ready}
            busy={busy}
            instant={reduceMotion === true}
            onCancel={cancel}
            onConfirm={() => void decide('approve', 'step')}
          />
        )}
      </AnimatePresence>

      <div className="decision-links">
        {detail && body === undefined && (
          <Button variant="quiet" aria-expanded={showCommand} aria-controls={commandId} onClick={() => setShowCommand((v) => !v)}>
            Show the command
          </Button>
        )}
        {!standalone && (
          <a className="decision-link" href={`#/approvals/${encodeURIComponent(s.id)}`}>
            Show details
          </a>
        )}
      </div>
      {detail && body === undefined && showCommand && (
        <pre id={commandId} className="decision-command mono">
          {actionText(detail.action) || '(no action recorded)'}
        </pre>
      )}
    </article>
  );
}

type ConfirmStepProps = {
  undo?: string;
  ready: boolean;
  busy: boolean;
  instant: boolean;
  onCancel: () => void;
  onConfirm: () => void;
};

// ConfirmStep is the inline "are you sure" under the buttons. While it
// animates out, AnimatePresence keeps rendering it with the props of its
// last live render, when Confirm was enabled. useIsPresent is the one
// live signal it still gets, so on the way out it disables its buttons,
// hides itself from assistive tech and takes no pointer events: a click
// in those 180ms cannot approve something the panel no longer offers.
function ConfirmStep({ undo, ready, busy, instant, onCancel, onConfirm }: ConfirmStepProps) {
  const present = useIsPresent();
  return (
    <m.div
      className={present ? 'confirm-step-wrap' : 'confirm-step-wrap is-closing'}
      aria-hidden={present ? undefined : true}
      inert={!present}
      initial={{ height: 0, opacity: 0 }}
      animate={{ height: 'auto', opacity: 1 }}
      exit={{ height: 0, opacity: 0 }}
      transition={{ duration: instant ? 0 : DUR.disclose, ease: EASE }}
    >
      <div
        className="confirm-step"
        role="group"
        aria-label="Confirm approval"
        onKeyDown={(e) => {
          if (present && e.key === 'Escape') onCancel();
        }}
      >
        <p>Approve this? The agent will be let through.</p>
        {undo !== undefined && (
          <p className="confirm-step-undo">
            To undo it later: <span>{undo}</span>
          </p>
        )}
        <div className="decision-buttons">
          <Button variant="quiet" onClick={onCancel} disabled={!present || busy}>
            Cancel
          </Button>
          <Button disabled={!present || !ready} onClick={present ? onConfirm : undefined}>
            Confirm approval
          </Button>
        </div>
      </div>
    </m.div>
  );
}
