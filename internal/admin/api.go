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
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/SaiPisey2/blastgate/internal/approval"
	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/normalize"
	"github.com/SaiPisey2/blastgate/internal/policy"
	"github.com/SaiPisey2/blastgate/internal/replay"
	"github.com/SaiPisey2/blastgate/internal/store"
)

// Deps is what serve hands the API: the store, the approval service that
// signs decisions, the policy it loaded (with its text and where the
// text came from, for the policy view), and the name of the cluster the
// gateway fronts, so an approver always sees where a decision lands.
type Deps struct {
	Store        *store.Store
	Approvals    *approval.Service
	Policy       *policy.Policy
	PolicySource string
	PolicyText   []byte
	Cluster      string
	Log          *slog.Logger
}

const (
	bodyLimit      = 64 << 10
	maxPolicyBytes = 64 << 10
	maxSinceHours  = 720
	feedLimit      = 50
	approvalsLimit = 200
	sessionsLimit  = 200
	listLimitMax   = 500
	bypassLimit    = 100
	bypassSince    = 24
	statsSince     = 168
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

	errSelfApproval   = "you can't approve a request made on your behalf"
	errSecondApprover = "you already approved this; it needs a second person"
	errReauth         = "sign in again to approve access grants"
	errChannel        = "access grants need two approvers in the browser"
)

// Ids are checked against their exact shape before any lookup: a path
// segment is attacker-chosen text, and one that cannot be an id never
// reaches the database, the logs or an error message.
var (
	approvalIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	sessionIDPattern  = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

var approvalStatuses = map[string]bool{"": true, "pending": true, "partially_approved": true, "approved": true, "denied": true,
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
	CountPendingApprovals(ctx context.Context, now time.Time) (int, error)
	ListLivePartialApprovals(ctx context.Context, now time.Time, limit int) ([]store.Approval, error)
	PolicyStats(ctx context.Context, since, now time.Time) ([]store.RuleStats, error)
	ApproverHumans(ctx context.Context, approverID string) ([]string, error)
	ApprovalByID(ctx context.Context, id string) (store.Approval, error)
	ListSessionsLimit(ctx context.Context, limit int) ([]store.Session, error)
	SessionByID(ctx context.Context, id string) (store.Session, error)
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
	// More specific than {id}, so the mux picks it for /count; "count" is
	// not an id either way (ids are 32 hex characters).
	mux.Handle("GET /api/approvals/count", a.Require(h.approvalCount))
	mux.Handle("GET /api/approvals/{id}", a.Require(h.approval))
	mux.Handle("POST /api/approvals/{id}/approve", a.Require(h.decide("approve")))
	mux.Handle("POST /api/approvals/{id}/deny", a.Require(h.decide("deny")))
	mux.Handle("GET /api/sessions", a.Require(h.sessions))
	mux.Handle("POST /api/sessions/{id}/revoke", a.Require(h.revoke))
	mux.Handle("GET /api/policy", a.Require(h.policy))
	mux.Handle("POST /api/policy/replay", a.Require(h.replay))
	mux.Handle("GET /api/policy/stats", a.Require(h.policyStats))
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
	reply(w, http.StatusOK, map[string]string{"name": u.ApproverName, "csrf": u.CSRF, "cluster": h.d.Cluster})
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
	// NeedsApprovers is 2 when the approval rules want two people, from
	// approval.NeedsTwo and never from the stored class: the class alone
	// would say 1 for a row whose impact no longer matches its digest,
	// and the UI would then offer a lone Approve that the server refuses.
	NeedsApprovers int    `json:"needs_approvers"`
	FirstApprover  string `json:"first_approver"`
	FirstApproved  string `json:"first_approved"`
	// SQLDetected lets the queue word an exec running a database client
	// without fetching each detail. It is trusted from the impact only
	// when the impact matches its digest; otherwise see sqlDetected.
	SQLDetected bool `json:"sql_detected"`
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
		NeedsApprovers: 1, FirstApprover: a.FirstApproverName, FirstApproved: rfc3339(a.FirstApproved),
	}
	if approval.NeedsTwo(a) {
		s.NeedsApprovers = 2
	}
	var imp engine.Impact
	decoded := json.Unmarshal(a.ImpactJSON, &imp) == nil
	if decoded {
		s.Summary, s.Class, s.DataDestroyed, s.Measured = imp.Summary(), imp.Class, imp.DataDestroyed, imp.Measured
	}
	s.SQLDetected = sqlDetected(decoded && imp.Digest() == a.ImpactDigest, imp, act, resource)
	// Nothing moves a lapsed pending approval to expired until the agent
	// retries, and it usually never does. Shown as pending, it would offer
	// Approve and Deny that can only ever answer 409. A partial approval
	// lapses the same way, waiting on a second person who came too late.
	if (a.Status == "pending" || a.Status == "partially_approved") && now.After(a.Expires) {
		s.Status = "expired"
	}
	if age := now.Sub(a.Created); age > 0 {
		s.AgeSeconds = int64(age / time.Second)
	}
	return s
}

// execSubresources are the pod subresources that run or attach to a
// process in a container: where a database client could be running.
var execSubresources = map[string]bool{"exec": true, "attach": true, "ephemeralcontainers": true}

// sqlDetected is the impact's own flag when the impact can be trusted
// (it decodes and matches the digest the token binds). When it cannot,
// a truncated row or one edited in the database, false would tell the
// approver an exec is harmless; so an exec-like request reads true and
// anything else false.
func sqlDetected(trusted bool, imp engine.Impact, act normalize.Action, resource string) bool {
	if trusted {
		return imp.SQLDetected
	}
	switch resource {
	case "pods/exec", "pods/attach", "pods/ephemeralcontainers":
		return true
	}
	return execSubresources[act.Subresource] || strings.HasSuffix(resource, "/exec")
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
		// The queue reaches as far as the stream's pending ids, so every
		// id the stream names is a card the queue shows. The count can go
		// past it: past 500 the badge says how many, the queue the oldest.
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
	switch status {
	case "pending":
		// The queue: only what can still be decided, oldest first.
		l, err = h.st.ListPendingApprovals(r.Context(), now, limit)
	case "partially_approved":
		// Live ones only, like the queue: a lapsed partial would be listed
		// under this filter only to read "expired".
		l, err = h.st.ListLivePartialApprovals(r.Context(), now, limit)
	default:
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

// approvalCount is the true size of the queue, for the badge before the
// stream's first event: the pending list stops at its limit, and its
// length would stop counting there too.
func (h *api) approvalCount(w http.ResponseWriter, r *http.Request, _ store.UISession) {
	n, err := h.st.CountPendingApprovals(r.Context(), h.auth.Now())
	if err != nil {
		h.internal(w, "count approvals", err)
		return
	}
	reply(w, http.StatusOK, map[string]int{"count": n})
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
			// The humans linked to this account are read at decision time,
			// from the store, never from the request: they are what makes
			// "bob approving alice's request" bob's own request when bob is
			// alice's account.
			humans, herr := h.st.ApproverHumans(r.Context(), u.ApproverID)
			if herr != nil {
				h.internal(w, "approver humans", herr)
				return
			}
			a, err = h.d.Approvals.Approve(r.Context(), id, approval.Approver{Name: u.ApproverName, ID: u.ApproverID,
				Humans: humans, SignedIn: u.Created, Channel: "ui"})
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
		// The rule refusals are told apart so the UI can say why: not
		// yours to approve, sign in again, or wait for a second person.
		// Their texts are fixed constants, so nothing about the request
		// is echoed back.
		case errors.Is(err, approval.ErrSelfApproval):
			fail(w, http.StatusForbidden, errSelfApproval)
			return
		case errors.Is(err, approval.ErrReauthRequired):
			fail(w, http.StatusForbidden, errReauth)
			return
		// Unreachable from here (this channel is always "ui"); mapped so a
		// later change cannot turn it into a 500.
		case errors.Is(err, approval.ErrChannelNotAllowed):
			fail(w, http.StatusForbidden, errChannel)
			return
		case errors.Is(err, approval.ErrNeedsSecondApprover):
			fail(w, http.StatusConflict, errSecondApprover)
			return
		case err != nil:
			h.internal(w, verb, err)
			return
		}
		// first_approver keeps both people of an access grant in the log
		// (ruling E-R3): the first approval's line names them, and so does
		// the second's.
		h.log.Info("approval decided", "id", id, "decision", a.Status, "by", u.ApproverName, "first_approver", a.FirstApproverName)
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
	// Every `session new` adds a row and none is ever deleted, so the page
	// is bounded like every other list here.
	limit, ok := listLimit(r, sessionsLimit)
	if !ok {
		fail(w, http.StatusBadRequest, errBadQuery)
		return
	}
	l, err := h.st.ListSessionsLimit(r.Context(), limit)
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
	s, err := h.st.SessionByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, errNotFound)
		return
	}
	if err != nil {
		h.internal(w, "session lookup", err)
		return
	}
	reply(w, http.StatusOK, sessionRow(s, now))
}

// ---- policy ----

func (h *api) policy(w http.ResponseWriter, r *http.Request, _ store.UISession) {
	reply(w, http.StatusOK, map[string]string{"source": h.d.PolicySource, "text": string(h.d.PolicyText)})
}

// RuleStatsRow is one rule's line in "How each rule is used".
// ApproveRate is approved/(approved+denied) to three decimals, and null
// when nothing was decided: 0 would read as "always denied".
type RuleStatsRow struct {
	Rule        string   `json:"rule"`
	Held        int      `json:"held"`
	Approved    int      `json:"approved"`
	Denied      int      `json:"denied"`
	Expired     int      `json:"expired"`
	ApproveRate *float64 `json:"approve_rate"`
}

type policyStatsReply struct {
	SinceHours int64          `json:"since_hours"`
	Rules      []RuleStatsRow `json:"rules"`
}

// policyStats is how each rule's holds ended over the last since_hours,
// so the operator can see a rule people approve every time.
func (h *api) policyStats(w http.ResponseWriter, r *http.Request, _ store.UISession) {
	since, ok := queryInt(r, "since_hours", statsSince, maxSinceHours)
	if !ok {
		fail(w, http.StatusBadRequest, errSince)
		return
	}
	now := h.auth.Now()
	l, err := h.st.PolicyStats(r.Context(), now.Add(-time.Duration(since)*time.Hour), now)
	if err != nil {
		h.internal(w, "policy stats", err)
		return
	}
	out := policyStatsReply{SinceHours: since, Rules: make([]RuleStatsRow, 0, len(l))}
	for _, s := range l {
		row := RuleStatsRow{Rule: s.Rule, Held: s.Held, Approved: s.Approved, Denied: s.Denied, Expired: s.Expired}
		if d := s.Approved + s.Denied; d > 0 {
			rate := math.Round(float64(s.Approved)/float64(d)*1000) / 1000
			row.ApproveRate = &rate
		}
		out.Rules = append(out.Rules, row)
	}
	reply(w, http.StatusOK, out)
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
