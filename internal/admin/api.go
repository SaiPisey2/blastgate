package admin

// This file is the approver UI's JSON API: the feed, the approval queue
// and its decisions, agent sessions, policy replay and bypass records.
// Every route but login runs behind Auth.Require, and no response ever
// carries a token, token hash, nonce or request body.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/SaiPisey2/blastgate/internal/approval"
	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/normalize"
	"github.com/SaiPisey2/blastgate/internal/policy"
	"github.com/SaiPisey2/blastgate/internal/replay"
	"github.com/SaiPisey2/blastgate/internal/store"
)

// Deps is what serve hands the API: the store, the approval service that
// signs decisions, and the policy it loaded (with its text and where the
// text came from, for the policy view).
type Deps struct {
	Store        *store.Store
	Approvals    *approval.Service
	Policy       *policy.Policy
	PolicySource string
	PolicyText   []byte
	Log          *slog.Logger
}

const (
	bodyLimit      = 64 << 10
	maxPolicyBytes = 64 << 10
	maxSinceHours  = 720
	feedLimit      = 50
	approvalsLimit = 200
	listLimitMax   = 500
	bypassLimit    = 100
	bypassSince    = 24
)

// replayRowCap bounds how many decision rows one replay loads and
// evaluates. Without it a 720-hour window on a busy gateway is one
// approver request that reads the whole audit table into memory. A var,
// not a const, so a test can lower it rather than seed 100,001 rows.
var replayRowCap = 100_000

// Every error body is one of these constants. The one exception is a
// replayed policy's parse error, which is the operator's own input echoed
// back, and the only way they can find the mistake in it.
const (
	errNotFound   = "not found"
	errNotPending = "approval is not pending"
	errBadQuery   = "bad query parameter"
	errBadBody    = "request body must be one JSON object of at most 64 KiB"
	errSince      = "since_hours must be between 1 and 720"
	errPolicySize = "policy larger than 64 KiB"
	errBadStatus  = "unknown approval status"
	errBusy       = "a replay is already running; try again when it finishes"
)

// Ids are checked against their exact shape before any lookup: a path
// segment is attacker-chosen text, and one that cannot be an id never
// reaches the database, the logs or an error message.
var (
	approvalIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	sessionIDPattern  = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

var approvalStatuses = map[string]bool{"": true, "pending": true, "approved": true, "denied": true,
	"consumed": true, "superseded": true, "expired": true}

// apiStore is the slice of *store.Store the API reads and writes. It is an
// interface only so a test can count calls and prove a malformed id never
// reached the store.
type apiStore interface {
	AuditPage(ctx context.Context, f store.AuditFilter) ([]store.AuditRow, error)
	AuditAfter(ctx context.Context, afterID int64, limit int) ([]store.AuditRow, error)
	AuditSinceLimit(ctx context.Context, since time.Time, kind string, limit int) ([]store.AuditRow, error)
	ListApprovalsLimit(ctx context.Context, status string, limit int) ([]store.Approval, error)
	ListPendingApprovals(ctx context.Context, now time.Time, limit int) ([]store.Approval, error)
	ApprovalByID(ctx context.Context, id string) (store.Approval, error)
	ListSessions(ctx context.Context) ([]store.Session, error)
	RevokeSession(ctx context.Context, id string, at time.Time) error
	BypassSince(ctx context.Context, since time.Time, limit int) ([]store.BypassRow, error)
}

type api struct {
	auth *Auth
	d    Deps
	st   apiStore
	log  *slog.Logger
	// replaySlot admits one replay at a time. Each holds up to
	// replayRowCap rows and burns CPU on CEL; several approvers (or one
	// double-clicking) must not multiply that.
	replaySlot chan struct{}
	// slots counts live streams, per UI session and in total.
	slots *streamSlots
}

// Routes mounts the whole /api surface on mux.
func Routes(mux *http.ServeMux, a *Auth, d Deps) { routes(mux, a, d, d.Store) }

// routes returns the api so a test can look at its stream slots.
func routes(mux *http.ServeMux, a *Auth, d Deps, st apiStore) *api {
	log := d.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &api{auth: a, d: d, st: st, log: log, replaySlot: make(chan struct{}, 1), slots: &streamSlots{per: map[string]int{}}}
	mux.HandleFunc("POST /api/login", a.Login)
	// Logout sits behind Require (the UI sends the CSRF header on it) so
	// that every /api route but login answers 401 without a live session;
	// a stale cookie is still cleared, by Require itself.
	mux.Handle("POST /api/logout", a.Require(func(w http.ResponseWriter, r *http.Request, _ store.UISession) { a.Logout(w, r) }))
	mux.Handle("GET /api/me", a.Require(h.me))
	mux.Handle("GET /api/feed", a.Require(h.feed))
	mux.Handle("GET /api/approvals", a.Require(h.approvals))
	mux.Handle("GET /api/approvals/{id}", a.Require(h.approval))
	mux.Handle("POST /api/approvals/{id}/approve", a.Require(h.decide("approve")))
	mux.Handle("POST /api/approvals/{id}/deny", a.Require(h.decide("deny")))
	mux.Handle("GET /api/sessions", a.Require(h.sessions))
	mux.Handle("POST /api/sessions/{id}/revoke", a.Require(h.revoke))
	mux.Handle("GET /api/policy", a.Require(h.policy))
	mux.Handle("POST /api/policy/replay", a.Require(h.replay))
	mux.Handle("GET /api/bypass", a.Require(h.bypass))
	mux.Handle("GET /api/stream", a.Require(h.stream))
	// Anything else under /api is a 401 without a session too, so probing
	// for routes learns nothing before logging in.
	mux.Handle("/api/", a.Require(func(w http.ResponseWriter, r *http.Request, _ store.UISession) {
		fail(w, http.StatusNotFound, errNotFound)
	}))
	return h
}

// reply writes v as JSON. no-store because every answer here is live
// state an approver acts on, and a cached queue or feed would be stale.
func reply(w http.ResponseWriter, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		code, b = http.StatusInternalServerError, []byte(errInternal)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	w.Write(b)
}

func fail(w http.ResponseWriter, code int, msg string) {
	reply(w, code, map[string]string{"error": msg})
}

func (h *api) internal(w http.ResponseWriter, what string, err error) {
	h.log.Error("admin api: "+what, "err", err)
	fail(w, http.StatusInternalServerError, "internal error")
}

// rfc3339 formats a time for the UI; a zero time (never decided) is "",
// not year 1.
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func (h *api) me(w http.ResponseWriter, r *http.Request, u store.UISession) {
	reply(w, http.StatusOK, map[string]string{"name": u.ApproverName, "csrf": u.CSRF})
}

// ---- feed ----

// ExportRow is one audit row as `blastgate audit export` writes it.
// Request bodies are never stored (only their digest), so none can appear
// here. Its fields and their order are the export's format: the CLI test
// TestAuditExportBytesAreStable pins the bytes.
type ExportRow struct {
	At            time.Time       `json:"at"`
	Kind          string          `json:"kind"`
	RequestID     string          `json:"request_id"`
	Session       string          `json:"session"`
	Human         string          `json:"human"`
	Agent         string          `json:"agent"`
	Source        string          `json:"source"`
	Verb          string          `json:"verb"`
	Group         string          `json:"group"`
	Resource      string          `json:"resource"`
	Subresource   string          `json:"subresource"`
	Namespace     string          `json:"namespace"`
	Name          string          `json:"name"`
	RequestDigest string          `json:"request_digest"`
	Class         string          `json:"class"`
	Measured      bool            `json:"measured"`
	Rule          string          `json:"rule"`
	Decision      string          `json:"decision"`
	ApprovalID    string          `json:"approval_id"`
	Status        int             `json:"status"`
	Outcome       string          `json:"outcome"`
	LatencyMS     int64           `json:"latency_ms"`
	Snapshot      string          `json:"snapshot"`
	Action        json.RawMessage `json:"action,omitempty"`
	Impact        json.RawMessage `json:"impact,omitempty"`
	Labels        json.RawMessage `json:"labels,omitempty"`
}

// FeedRow is the export row plus the audit row's id, which the feed pages
// by (before=) and the live stream dedupes by. The id is kept out of
// ExportRow itself so the CLI's export stays byte-for-byte what it was.
type FeedRow struct {
	ID int64 `json:"id"`
	ExportRow
}

func ToExport(r store.AuditRow) ExportRow {
	return ExportRow{
		At: r.At, Kind: r.Kind, RequestID: r.RequestID, Session: r.Session, Human: r.Human, Agent: r.Agent,
		Source: r.Source, Verb: r.Verb, Group: r.Group, Resource: r.Resource, Subresource: r.Subresource,
		Namespace: r.Namespace, Name: r.Name, RequestDigest: r.RequestDigest, Class: r.Class,
		Measured: r.Measured, Rule: r.Rule, Decision: r.Decision, ApprovalID: r.ApprovalID,
		Status: r.Status, Outcome: r.Outcome, LatencyMS: r.LatencyMS, Snapshot: r.Snapshot,
		Action: rawJSON(r.ActionJSON), Impact: rawJSON(r.ImpactJSON), Labels: rawJSON(r.LabelsJSON),
	}
}

func ToFeedRow(r store.AuditRow) FeedRow { return FeedRow{ID: r.ID, ExportRow: ToExport(r)} }

// rawJSON embeds a stored JSON column as itself. An empty column is left
// out; one that is somehow not valid JSON is exported as a string, since
// a RawMessage that is not JSON would fail the whole line.
func rawJSON(b []byte) json.RawMessage {
	if len(b) == 0 {
		return nil
	}
	if json.Valid(b) {
		return json.RawMessage(b)
	}
	s, _ := json.Marshal(string(b))
	return s
}

// queryInt reads an optional positive integer parameter. Absent is def;
// present but not an integer in [1, max] is an error, never a silent
// default: a UI asking for page 0 has a bug worth seeing.
func queryInt(r *http.Request, name string, def, max int64) (int64, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 || n > max {
		return 0, false
	}
	return n, true
}

// listLimit reads a list's optional limit. Over listLimitMax is clamped,
// not refused: asking for "a lot" is not a mistake, only a bound to keep.
// The clamp happens on the int64, before any narrowing to int.
func listLimit(r *http.Request, def int64) (int, bool) {
	n, ok := queryInt(r, "limit", def, 1<<62)
	return int(min(n, listLimitMax)), ok
}

func (h *api) feed(w http.ResponseWriter, r *http.Request, _ store.UISession) {
	before, ok1 := queryInt(r, "before", 0, 1<<62)
	limit, ok2 := listLimit(r, feedLimit)
	if !ok1 || !ok2 {
		fail(w, http.StatusBadRequest, errBadQuery)
		return
	}
	q := r.URL.Query()
	rows, err := h.st.AuditPage(r.Context(), store.AuditFilter{
		BeforeID: before, Limit: limit,
		Agent: q.Get("agent"), Human: q.Get("human"), Class: q.Get("class"), Decision: q.Get("decision"), Kind: q.Get("kind"),
	})
	if err != nil {
		h.internal(w, "audit page", err)
		return
	}
	out := make([]FeedRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, ToFeedRow(row))
	}
	reply(w, http.StatusOK, out)
}

// ---- approvals ----

type ApprovalSummary struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	Rule          string `json:"rule"`
	Human         string `json:"human"`
	Agent         string `json:"agent"`
	Verb          string `json:"verb"`
	Resource      string `json:"resource"`
	Namespace     string `json:"namespace"`
	Name          string `json:"name"`
	Summary       string `json:"summary"`
	Class         string `json:"class"`
	DataDestroyed int    `json:"data_destroyed"`
	// Measured is false for an unmeasured hold (an exec, a proxied
	// request, a scoring timeout), whose data_destroyed is 0 because
	// nothing was measured, and for an impact that does not parse. The
	// queue demands the typed confirmation for it (P2-R29).
	Measured   bool   `json:"measured"`
	AgeSeconds int64  `json:"age_seconds"`
	Created    string `json:"created"`
	Expires    string `json:"expires"`
}

// ApprovalDetail is everything the human is deciding on. It is built
// field by field from the row, never by marshalling store.Approval, which
// holds the nonce and the release token.
type ApprovalDetail struct {
	ApprovalSummary
	Action    json.RawMessage `json:"action"`
	Impact    json.RawMessage `json:"impact"`
	DecidedBy string          `json:"decided_by"`
	Decided   string          `json:"decided"`
}

func summarize(a store.Approval, now time.Time) ApprovalSummary {
	var act normalize.Action
	json.Unmarshal(a.ActionJSON, &act)
	// A write to pods/exec is a create on pods; shown without its
	// subresource the approver would read "create pods" for what is
	// really a command run in a container. Joined the way replay joins it.
	resource := act.Resource
	if act.Subresource != "" {
		resource += "/" + act.Subresource
	}
	s := ApprovalSummary{
		ID: a.ID, Status: a.Status, Rule: a.Rule, Human: a.Human, Agent: a.Agent,
		Verb: act.Verb, Resource: resource, Namespace: act.Namespace, Name: act.Name,
		Summary: "unknown impact", Created: rfc3339(a.Created), Expires: rfc3339(a.Expires),
	}
	var imp engine.Impact
	if json.Unmarshal(a.ImpactJSON, &imp) == nil {
		s.Summary, s.Class, s.DataDestroyed, s.Measured = imp.Summary(), imp.Class, imp.DataDestroyed, imp.Measured
	}
	// Nothing moves a lapsed pending approval to expired until the agent
	// retries, and it usually never does. Shown as pending, it would offer
	// Approve and Deny that can only ever answer 409.
	if a.Status == "pending" && now.After(a.Expires) {
		s.Status = "expired"
	}
	if age := now.Sub(a.Created); age > 0 {
		s.AgeSeconds = int64(age / time.Second)
	}
	return s
}

func detail(a store.Approval, now time.Time) ApprovalDetail {
	d := ApprovalDetail{ApprovalSummary: summarize(a, now), DecidedBy: a.DecidedBy, Decided: rfc3339(a.Decided)}
	d.Action, d.Impact = objectJSON(a.ActionJSON), objectJSON(a.ImpactJSON)
	return d
}

// objectJSON passes a stored JSON column through as itself, or null if it
// is not JSON: the UI reads action and impact as objects, and a string
// standing in for one would render as garbage rather than as "unknown".
func objectJSON(b []byte) json.RawMessage {
	if len(b) == 0 || !json.Valid(b) {
		return json.RawMessage("null")
	}
	return json.RawMessage(b)
}

func (h *api) approvals(w http.ResponseWriter, r *http.Request, _ store.UISession) {
	status := r.URL.Query().Get("status")
	if !approvalStatuses[status] {
		fail(w, http.StatusBadRequest, errBadStatus)
		return
	}
	def := int64(approvalsLimit)
	if status == "pending" {
		// The queue reaches as far as the stream's pending count, so the
		// badge never counts cards the queue does not show.
		def = streamPendingLimit
	}
	limit, ok := listLimit(r, def)
	if !ok {
		fail(w, http.StatusBadRequest, errBadQuery)
		return
	}
	now := h.auth.Now()
	var l []store.Approval
	var err error
	if status == "pending" {
		// The queue: only what can still be decided, oldest first.
		l, err = h.st.ListPendingApprovals(r.Context(), now, limit)
	} else {
		l, err = h.st.ListApprovalsLimit(r.Context(), status, limit)
	}
	if err != nil {
		h.internal(w, "list approvals", err)
		return
	}
	out := make([]ApprovalSummary, 0, len(l))
	for _, a := range l {
		out = append(out, summarize(a, now))
	}
	reply(w, http.StatusOK, out)
}

func (h *api) approval(w http.ResponseWriter, r *http.Request, _ store.UISession) {
	id := r.PathValue("id")
	if !approvalIDPattern.MatchString(id) {
		fail(w, http.StatusNotFound, errNotFound)
		return
	}
	a, err := h.st.ApprovalByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, errNotFound)
		return
	}
	if err != nil {
		h.internal(w, "approval lookup", err)
		return
	}
	reply(w, http.StatusOK, detail(a, h.auth.Now()))
}

// decide is approve and deny. Who decided is the signed-in approver and
// nothing else: the request body is never read, so a body naming someone
// else cannot put their name on the decision.
func (h *api) decide(verb string) func(http.ResponseWriter, *http.Request, store.UISession) {
	return func(w http.ResponseWriter, r *http.Request, u store.UISession) {
		id := r.PathValue("id")
		if !approvalIDPattern.MatchString(id) {
			fail(w, http.StatusNotFound, errNotFound)
			return
		}
		var a store.Approval
		var err error
		if verb == "approve" {
			a, err = h.d.Approvals.Approve(r.Context(), id, u.ApproverName)
		} else {
			a, err = h.d.Approvals.Deny(r.Context(), id, u.ApproverName)
		}
		switch {
		case errors.Is(err, store.ErrNotFound):
			fail(w, http.StatusNotFound, errNotFound)
			return
		// ErrConflict is a concurrent decision that won the race; to this
		// approver it is the same as finding it already decided.
		case errors.Is(err, approval.ErrNotPending), errors.Is(err, store.ErrConflict):
			fail(w, http.StatusConflict, errNotPending)
			return
		case err != nil:
			h.internal(w, verb, err)
			return
		}
		h.log.Info("approval decided", "id", id, "decision", a.Status, "by", u.ApproverName)
		reply(w, http.StatusOK, detail(a, h.auth.Now()))
	}
}

// ---- agent sessions ----

type SessionRow struct {
	ID      string `json:"id"`
	Human   string `json:"human"`
	Agent   string `json:"agent"`
	Created string `json:"created"`
	Expires string `json:"expires"`
	State   string `json:"state"` // active | expired | revoked
}

func sessionRow(s store.Session, now time.Time) SessionRow {
	state := "active"
	switch {
	case !s.Revoked.IsZero():
		state = "revoked"
	case !now.Before(s.Expires):
		state = "expired"
	}
	return SessionRow{ID: s.ID, Human: s.Human, Agent: s.Agent, Created: rfc3339(s.Created), Expires: rfc3339(s.Expires), State: state}
}

func (h *api) sessions(w http.ResponseWriter, r *http.Request, _ store.UISession) {
	l, err := h.st.ListSessions(r.Context())
	if err != nil {
		h.internal(w, "list sessions", err)
		return
	}
	now := h.auth.Now()
	out := make([]SessionRow, 0, len(l))
	for _, s := range l {
		out = append(out, sessionRow(s, now))
	}
	reply(w, http.StatusOK, out)
}

// revoke ends an agent session at once: the proxy's authenticator reads
// revoked_at on every request. The answer is the session as it now
// stands, so the UI can redraw the row without a second request.
func (h *api) revoke(w http.ResponseWriter, r *http.Request, u store.UISession) {
	id := r.PathValue("id")
	if !sessionIDPattern.MatchString(id) {
		fail(w, http.StatusNotFound, errNotFound)
		return
	}
	now := h.auth.Now()
	err := h.st.RevokeSession(r.Context(), id, now)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, errNotFound)
		return
	}
	if err != nil {
		h.internal(w, "revoke session", err)
		return
	}
	h.log.Info("agent session revoked", "session", id, "by", u.ApproverName)
	l, err := h.st.ListSessions(r.Context())
	if err != nil {
		h.internal(w, "list sessions", err)
		return
	}
	for _, s := range l {
		if s.ID == id {
			reply(w, http.StatusOK, sessionRow(s, now))
			return
		}
	}
	fail(w, http.StatusNotFound, errNotFound)
}

// ---- policy ----

func (h *api) policy(w http.ResponseWriter, r *http.Request, _ store.UISession) {
	reply(w, http.StatusOK, map[string]string{"source": h.d.PolicySource, "text": string(h.d.PolicyText)})
}

type replayRequest struct {
	Policy     string `json:"policy"`
	SinceHours int    `json:"since_hours"`
}

// readReplay decodes exactly one JSON object with only the two known
// keys, within bodyLimit, and nothing after it.
func readReplay(w http.ResponseWriter, r *http.Request) (replayRequest, bool) {
	var req replayRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, bodyLimit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return req, false
	}
	return req, true
}

// replay re-evaluates the recorded decisions of the last since_hours under
// a candidate policy, with the same code the CLI's replay runs. Nothing
// is changed: the candidate is parsed, used and dropped.
func (h *api) replay(w http.ResponseWriter, r *http.Request, _ store.UISession) {
	req, ok := readReplay(w, r)
	if !ok {
		fail(w, http.StatusBadRequest, errBadBody)
		return
	}
	if req.SinceHours < 1 || req.SinceHours > maxSinceHours {
		fail(w, http.StatusBadRequest, errSince)
		return
	}
	// Unreachable today: MaxBytesReader already caps the body at 64 KiB,
	// and a decoded JSON string is never longer than its encoding. Kept so
	// the policy's own limit survives a later change to the body limit.
	if len(req.Policy) > maxPolicyBytes {
		fail(w, http.StatusBadRequest, errPolicySize)
		return
	}
	p, err := policy.Load([]byte(req.Policy))
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	select {
	case h.replaySlot <- struct{}{}:
		defer func() { <-h.replaySlot }()
	default:
		fail(w, http.StatusTooManyRequests, errBusy)
		return
	}
	// One row past the cap says whether the window held more than was
	// evaluated, without counting the whole window. The rows are the
	// window's newest, oldest first, so the extra one is the oldest and
	// is dropped from the front (P2-R21).
	rowCap := replayRowCap
	rows, err := h.st.AuditSinceLimit(r.Context(), h.auth.Now().Add(-time.Duration(req.SinceHours)*time.Hour), "decision", rowCap+1)
	if err != nil {
		h.internal(w, "audit since", err)
		return
	}
	truncated := len(rows) > rowCap
	if truncated {
		rows = rows[len(rows)-rowCap:]
	}
	// Run lists at most replay.MaxChanges and keeps counting Changed, so
	// the UI can say "showing 500 of N". It stops when the approver goes
	// away; there is then nobody to answer.
	res, err := replay.Run(r.Context(), rows, p)
	if err != nil {
		return
	}
	res.Truncated = truncated
	if res.Changes == nil {
		res.Changes = []replay.Change{}
	}
	reply(w, http.StatusOK, res)
}

// ---- bypass ----

type BypassRow struct {
	At          string   `json:"at"`
	User        string   `json:"user"`
	Groups      []string `json:"groups"`
	Verb        string   `json:"verb"`
	Group       string   `json:"group"`
	Resource    string   `json:"resource"`
	Subresource string   `json:"subresource"`
	Namespace   string   `json:"namespace"`
	Name        string   `json:"name"`
	UID         string   `json:"uid"`
	DryRun      bool     `json:"dry_run"`
}

func (h *api) bypass(w http.ResponseWriter, r *http.Request, _ store.UISession) {
	since, ok1 := queryInt(r, "since_hours", bypassSince, maxSinceHours)
	// BypassSince passes limit straight to SQL; every controller in the
	// cluster writes to this table, so listLimit's cap is what bounds it.
	limit, ok2 := listLimit(r, bypassLimit)
	if !ok1 || !ok2 {
		fail(w, http.StatusBadRequest, errBadQuery)
		return
	}
	l, err := h.st.BypassSince(r.Context(), h.auth.Now().Add(-time.Duration(since)*time.Hour), limit)
	if err != nil {
		h.internal(w, "bypass since", err)
		return
	}
	out := make([]BypassRow, 0, len(l))
	for _, b := range l {
		groups := b.Groups
		if groups == nil {
			groups = []string{}
		}
		out = append(out, BypassRow{At: rfc3339(b.At), User: b.User, Groups: groups, Verb: b.Verb, Group: b.Group,
			Resource: b.Resource, Subresource: b.Subresource, Namespace: b.Namespace, Name: b.Name, UID: b.UID, DryRun: b.DryRun})
	}
	reply(w, http.StatusOK, out)
}
