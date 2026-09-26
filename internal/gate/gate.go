// Package gate is the proxy's single decision step: every request is
// normalised, every write is scored and put to the policy, and the answer
// is allow, deny or hold. Nothing here forwards a write it has not first
// snapshotted and recorded; any step that cannot be completed refuses the
// request rather than letting it through.
package gate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/SaiPisey2/blastgate/internal/approval"
	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/normalize"
	"github.com/SaiPisey2/blastgate/internal/policy"
	"github.com/SaiPisey2/blastgate/internal/store"
)

type Assessor interface {
	Assess(ctx context.Context, a normalize.Action, body []byte) engine.Assessment
}

type Snapshotter interface {
	Take(ctx context.Context, requestID string, a normalize.Action, i engine.Impact) (string, error)
	// Discard removes a snapshot taken for a request that will not be
	// forwarded after all, so it is not later mistaken for the undo
	// bundle of a write that happened.
	Discard(path string)
}

type Audit interface {
	AppendAudit(ctx context.Context, r store.AuditRow) error
}

// Approvals is the approval lifecycle as the gate sees it. Verify's
// session, human and agent are always the authenticated session's (ruling
// P1-R9): the token is bound to them, and taking them from the request
// would let a caller present someone else's approval as its own.
//
// Verify never spends an approval; Consume does, and the gate calls it
// only once the snapshot is on disk (final review I2). Spending first
// meant a snapshot that then failed burned the human's approval for a
// request that was never forwarded and could never be released again.
type Approvals interface {
	Verify(ctx context.Context, session, human, agent, requestDigest, impactDigest string) (approval.Outcome, store.Approval, error)
	// Consume returns store.ErrConflict when the approval can no longer
	// be spent -- a concurrent retry spent it, or it lapsed.
	Consume(ctx context.Context, a store.Approval) error
	CreatePending(ctx context.Context, a store.Approval) error
	Status(ctx context.Context, id string) (string, error)
}

type Gate struct {
	Engine    Assessor
	Policy    *policy.Policy
	Approvals Approvals
	Audit     Audit
	Snapshots Snapshotter
	// SnapshotBudget bounds the snapshot taken before a write is
	// forwarded; past it, the write is refused. Zero means
	// defaultSnapshotBudget.
	SnapshotBudget time.Duration
	Hold           time.Duration
	Poll           time.Duration
	Now            func() time.Time
	Log            *slog.Logger
}

// Verdict is what the proxy does with one request. Message is the only
// text a client sees: blastgate's constant wording plus approval IDs,
// counts, class names and rule names -- never object names, request or
// session data, or error text, because the agent can write all of those.
type Verdict struct {
	Forward bool
	Code    int
	Reason  metav1.StatusReason
	Message string
	Ticket  string

	requestID string
	sess      store.Session
	act       normalize.Action
	digest    string
	scored    bool
	imp       engine.Impact
	labels    map[string]string

	rule, decision, approvalID, snapshot string
}

const (
	msgUnparseable = "blastgate: this request is not one blastgate understands, so it is refused"
	msgSnapshot    = "blastgate: could not snapshot before forwarding, so the request was not forwarded"
	msgAudit       = "blastgate: could not record the decision, so the request was not forwarded"
	msgApprovals   = "blastgate: could not check approvals, so the request was not forwarded"
	msgSpent       = "blastgate: this approval was already used by another request, so this one was not forwarded"
	msgChanged     = " The measured impact changed since the last approval."
	defaultPoll    = 500 * time.Millisecond
	// defaultSnapshotBudget matches the default score budget: a snapshot
	// reads what scoring already read, and a wedged read must not hold a
	// request past its client's own timeout.
	defaultSnapshotBudget = 5 * time.Second
	auditTimeout          = 5 * time.Second
)

// Decide runs the whole decision for one request. It never returns
// Forward: true for a write unless the write was measured, allowed (by
// policy or by a released approval), snapshotted and its decision row
// written.
func (g *Gate) Decide(ctx context.Context, s store.Session, r *http.Request, body []byte) Verdict {
	start := time.Now()
	v := Verdict{requestID: newRequestID(), sess: s}
	a, err := normalize.FromRequest(r, normalize.Principal{Session: s.ID, Human: s.Human, Agent: s.Agent})
	if err != nil {
		// Whatever the parser could not place, nobody can score; a write
		// blastgate does not understand is exactly the one not to pass.
		v.rule, v.decision = "unparseable", string(policy.Deny)
		return g.refuse(ctx, v, http.StatusForbidden, metav1.StatusReasonForbidden, msgUnparseable)
	}
	v.act = a
	if a.IsRead() {
		v.rule, v.decision, v.Forward = "read", string(policy.Allow), true
		// Not scored, but known: the engine's own read case says the same.
		// Without it the row's class is "", which the UI must show as
		// unmeasured (severe), and every allowed get would look alarming.
		v.imp = engine.Impact{Class: engine.ClassRead, Measured: true, Undo: "none"}
		return v
	}
	asm := g.Engine.Assess(ctx, a, body)
	v.digest = normalize.RequestDigest(a, body)
	// Labels pass through as-is: nil means the lookup failed, and policy
	// relies on that to hold rules that read labels (ruling P1-R7).
	v.scored, v.imp, v.labels = true, asm.Impact, asm.NamespaceLabels
	pv := g.Policy.Evaluate(ctx, a, asm.Impact, asm.NamespaceLabels)
	v.rule, v.decision = pv.Rule, string(pv.Decision)
	switch pv.Decision {
	case policy.Allow:
		return g.forward(ctx, v, nil)
	case policy.Hold:
		return g.hold(ctx, v, body, start)
	default:
		// Deny, and any decision this build does not know: refusing is the
		// only answer that cannot be wrong in the dangerous direction.
		return g.refuse(ctx, v, http.StatusForbidden, metav1.StatusReasonForbidden, "blastgate: refused by policy rule "+pv.Rule)
	}
}

func (g *Gate) hold(ctx context.Context, v Verdict, body []byte, start time.Time) Verdict {
	s := v.sess
	out, ap, err := g.Approvals.Verify(ctx, s.ID, s.Human, s.Agent, v.digest, v.imp.Digest())
	if err != nil {
		g.log().Error("approval check failed", "request", v.requestID, "err", err)
		return g.refuse(ctx, v, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable, msgApprovals)
	}
	changed := false
	var id string
	switch out {
	case approval.Verified:
		v.approvalID = ap.ID
		return g.forward(ctx, v, &ap)
	case approval.Denied:
		v.approvalID = ap.ID
		return g.denied(ctx, v)
	case approval.Pending:
		id = ap.ID
	default:
		// Void (the approval no longer matches what this request would
		// do), None, or an outcome this build does not know: all need a
		// fresh approval for the impact as measured now.
		changed = out == approval.Void
		if id, err = g.createPending(ctx, v); err != nil {
			return g.refuse(ctx, v, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable, msgApprovals)
		}
	}
	v.approvalID = id

	// The window counts from the start of the request, not of the wait:
	// scoring already used part of it, and the client's own timeout (60s
	// for kubectl) runs from when it sent the request.
	switch g.wait(ctx, id, g.Hold-time.Since(start)) {
	case "approved":
		return g.recheck(ctx, v, body, changed)
	case "denied":
		return g.denied(ctx, v)
	default:
		return g.ticket(ctx, v, id, changed)
	}
}

// recheck releases a request approved while it waited. It re-scores
// first: the human approved the impact measured when the hold began, and
// up to the whole hold window may have passed since. Checking with that
// old measurement would forward on a cluster that may no longer match it.
func (g *Gate) recheck(ctx context.Context, v Verdict, body []byte, changed bool) Verdict {
	asm := g.Engine.Assess(ctx, v.act, body)
	if ctx.Err() != nil {
		// The client left mid-measurement. The cut-short measurement would
		// digest differently and supersede an approval the human just gave;
		// leave it for the agent's retry to spend instead.
		return g.ticket(ctx, v, v.approvalID, changed)
	}
	v.imp, v.labels = asm.Impact, asm.NamespaceLabels
	// The approval covers the hold, not a refusal: if the cluster has
	// moved so that policy now denies this request outright, no human
	// "yes" given for the earlier measurement may override that.
	pv := g.Policy.Evaluate(ctx, v.act, asm.Impact, asm.NamespaceLabels)
	switch pv.Decision {
	case policy.Allow:
		// Still passes through the approval: releasing without spending
		// it would leave a live token for a request that has already run.
	case policy.Hold:
		v.rule = pv.Rule
	default:
		v.rule, v.decision = pv.Rule, string(pv.Decision)
		return g.refuse(ctx, v, http.StatusForbidden, metav1.StatusReasonForbidden, "blastgate: refused by policy rule "+pv.Rule)
	}
	s := v.sess
	out, ap, err := g.Approvals.Verify(ctx, s.ID, s.Human, s.Agent, v.digest, asm.Impact.Digest())
	if err != nil {
		g.log().Error("approval check failed", "request", v.requestID, "err", err)
		return g.refuse(ctx, v, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable, msgApprovals)
	}
	switch out {
	case approval.Verified:
		v.approvalID = ap.ID
		return g.forward(ctx, v, &ap)
	case approval.Denied:
		v.approvalID = ap.ID
		return g.denied(ctx, v)
	case approval.Pending:
		return g.ticket(ctx, v, v.approvalID, changed)
	default:
		// Void (superseded by this Verify), None (spent by a concurrent
		// identical request, expired, or otherwise gone) or unknown: the
		// old approval can never be approved again, so a ticket naming it
		// would send the human to approve something impossible.
		id, err := g.createPending(ctx, v)
		if err != nil {
			return g.refuse(ctx, v, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable, msgApprovals)
		}
		v.approvalID = id
		return g.ticket(ctx, v, id, out == approval.Void || changed)
	}
}

func (g *Gate) createPending(ctx context.Context, v Verdict) (string, error) {
	actJSON, _ := json.Marshal(v.act)
	impJSON, _ := json.Marshal(v.imp)
	s := v.sess
	a := store.Approval{
		ID: approval.NewID(), Session: s.ID, Human: s.Human, Agent: s.Agent,
		RequestDigest: v.digest, ImpactDigest: v.imp.Digest(),
		ActionJSON: actJSON, ImpactJSON: impJSON, Rule: v.rule,
		Status: "pending", Created: g.now(),
	}
	if err := g.Approvals.CreatePending(ctx, a); err != nil {
		g.log().Error("creating pending approval failed", "request", v.requestID, "err", err)
		return "", err
	}
	return a.ID, nil
}

// wait polls the approval until it is decided, the window runs out or the
// client goes away. It returns "approved", "denied", or "" for anything
// else. A failed Status read is not a decision; it keeps waiting.
func (g *Gate) wait(ctx context.Context, id string, window time.Duration) string {
	if window <= 0 {
		return ""
	}
	poll := g.Poll
	if poll <= 0 {
		poll = defaultPoll
	}
	deadline := time.NewTimer(window)
	defer deadline.Stop()
	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			// A client that stopped listening cannot receive a forwarded
			// response; holding the request open would only pin resources.
			return ""
		case <-deadline.C:
			return ""
		case <-tick.C:
		}
		st, err := g.Approvals.Status(ctx, id)
		if err != nil {
			g.log().Warn("approval status read failed", "approval", id, "err", err)
			continue
		}
		switch st {
		case "approved", "denied":
			return st
		case "pending", "":
			continue
		default:
			// consumed, superseded, expired: it will never be approved
			// from here, so there is nothing left to wait for.
			return ""
		}
	}
}

// forward snapshots, records the decision, spends the approval (when one
// released this request) and only then says forward. Any step failing
// refuses: a write without a snapshot cannot be undone, a write without a
// decision row is one the audit trail would never show, and an approval
// must be spent by exactly the request that runs. The approval is spent
// last so that none of the steps before it can burn it for a request that
// is then not forwarded -- a failed snapshot or audit leaves it for the
// agent's next retry.
func (g *Gate) forward(ctx context.Context, v Verdict, ap *store.Approval) Verdict {
	path, err := g.snapshot(ctx, v)
	if err != nil {
		g.log().Error("snapshot failed", "request", v.requestID, "err", err)
		return g.refuse(ctx, v, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable, msgSnapshot)
	}
	v.snapshot = path
	if err := g.appendAudit(ctx, g.row(v, "decision")); err != nil {
		g.log().Error("decision audit failed", "request", v.requestID, "err", err)
		g.Snapshots.Discard(path)
		// No second attempt at the decision row: the write just failed, and
		// the result row from Complete still records the refusal.
		return g.status(v, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable, msgAudit)
	}
	if ap != nil {
		if ctx.Err() != nil {
			// The client has gone: nothing forwarded could reach it, so the
			// approval stays unspent for its retry.
			g.Snapshots.Discard(path)
			return g.status(v, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable, msgApprovals)
		}
		// Detached from the client: a consume that commits just as the
		// request ctx is cancelled would otherwise report a failure for
		// an approval it did spend.
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
		err := g.Approvals.Consume(cctx, *ap)
		cancel()
		if err != nil {
			g.Snapshots.Discard(path)
			// The decision row is already written; the result row records
			// the refusal, so neither path writes a second decision row.
			if errors.Is(err, store.ErrConflict) {
				return g.status(v, http.StatusConflict, metav1.StatusReasonConflict, msgSpent)
			}
			g.log().Error("approval consume failed", "request", v.requestID, "err", err)
			return g.status(v, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable, msgApprovals)
		}
	}
	v.Forward = true
	return v
}

// snapshot takes the undo snapshot within SnapshotBudget. A snapshot that
// finishes past the limit is discarded and refused like a failed one:
// parts of it may have been cut short, and a read that hangs must not
// hold the request open past the client's own timeout.
func (g *Gate) snapshot(ctx context.Context, v Verdict) (string, error) {
	budget := g.SnapshotBudget
	if budget <= 0 {
		budget = defaultSnapshotBudget
	}
	sctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	path, err := g.Snapshots.Take(sctx, v.requestID, v.act, v.imp)
	if err != nil {
		return "", err
	}
	if err := sctx.Err(); err != nil {
		g.Snapshots.Discard(path)
		return "", fmt.Errorf("snapshot did not finish in time: %w", err)
	}
	return path, nil
}

func (g *Gate) denied(ctx context.Context, v Verdict) Verdict {
	return g.refuse(ctx, v, http.StatusForbidden, metav1.StatusReasonForbidden,
		fmt.Sprintf("blastgate: approval %s was denied; this request will not be forwarded", v.approvalID))
}

func (g *Gate) ticket(ctx context.Context, v Verdict, id string, changed bool) Verdict {
	v.Ticket = id
	// Addressed to a person, not to the agent reading it: an agent told
	// "approve with ..." may try to run the command itself. It cannot
	// succeed without the signing key and data directory, which the
	// README says to keep out of its environment, but it must not be
	// invited to try.
	msg := fmt.Sprintf("blastgate: held for approval %s (rule %s: %s). Ask a person to approve it with `blastgate approve %s --by <name>`, then retry.", id, v.rule, v.imp.Summary(), id)
	if changed {
		msg += msgChanged
	}
	return g.refuse(ctx, v, http.StatusForbidden, metav1.StatusReasonForbidden, msg)
}

// refuse records the decision for a request that will not be forwarded.
// Its audit failure is logged, not returned: the request is refused
// either way, and the result row still records it.
func (g *Gate) refuse(ctx context.Context, v Verdict, code int, reason metav1.StatusReason, msg string) Verdict {
	v = g.status(v, code, reason, msg)
	if err := g.appendAudit(ctx, g.row(v, "decision")); err != nil {
		g.log().Error("decision audit failed", "request", v.requestID, "err", err)
	}
	return v
}

func (g *Gate) status(v Verdict, code int, reason metav1.StatusReason, msg string) Verdict {
	v.Forward, v.Code, v.Reason, v.Message = false, code, reason, msg
	return v
}

// Complete appends the result row once the request has ended, reads
// included. An error is only logged: the request already happened, and
// failing now could not undo it.
func (g *Gate) Complete(ctx context.Context, v Verdict, status int, outcome string, latency time.Duration) {
	r := g.row(v, "result")
	r.Status, r.Outcome, r.LatencyMS = status, outcome, latency.Milliseconds()
	if err := g.appendAudit(ctx, r); err != nil {
		g.log().Error("result audit failed", "request", v.requestID, "err", err)
	}
}

// row builds an audit row. Decision is the policy's decision, not what
// happened to the request: a held request released by an approval stays
// "hold" with its approval ID, so replaying the trail under a new policy
// compares like with like. What happened is the result row's status.
func (g *Gate) row(v Verdict, kind string) store.AuditRow {
	a := v.act
	r := store.AuditRow{
		At:            g.now(),
		Kind:          kind,
		RequestID:     v.requestID,
		Session:       v.sess.ID,
		Human:         v.sess.Human,
		Agent:         v.sess.Agent,
		Source:        a.Source,
		Verb:          a.Verb,
		Group:         a.Group,
		Resource:      a.Resource,
		Subresource:   a.Subresource,
		Namespace:     a.Namespace,
		Name:          a.Name,
		RequestDigest: v.digest,
		Rule:          v.rule,
		Decision:      v.decision,
		ApprovalID:    v.approvalID,
		Snapshot:      v.snapshot,
	}
	if a.Verb != "" {
		r.ActionJSON, _ = json.Marshal(a)
	}
	// Class is set for reads too, which are known without scoring; the
	// impact and labels only for what was actually assessed.
	if v.imp.Class != "" {
		r.Class, r.Measured = v.imp.Class, v.imp.Measured
	}
	if v.scored {
		r.ImpactJSON, _ = json.Marshal(v.imp)
		// nil marshals to "null" and an empty map to "{}", so replay can
		// still tell "labels unknown" from "no labels".
		r.LabelsJSON, _ = json.Marshal(v.labels)
	}
	return r
}

// appendAudit detaches the write from the request's cancellation: a
// client that gives up mid-hold is exactly the request whose held
// decision must still reach the trail, and a cancelled ctx would drop it.
// The timeout keeps a wedged database from pinning the request forever.
func (g *Gate) appendAudit(ctx context.Context, r store.AuditRow) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	return g.Audit.AppendAudit(ctx, r)
}

func (g *Gate) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Gate) log() *slog.Logger {
	if g.Log != nil {
		return g.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newRequestID ties a request's decision row, result row and snapshot
// together; crypto/rand so IDs never collide across restarts.
func newRequestID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
