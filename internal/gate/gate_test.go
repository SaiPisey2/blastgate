package gate

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SaiPisey2/blastgate/internal/approval"
	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/normalize"
	"github.com/SaiPisey2/blastgate/internal/policy"
	"github.com/SaiPisey2/blastgate/internal/store"
)

type fakeEngine struct {
	imp   engine.Impact
	calls int
	later *engine.Impact // when set, returned from the second call on
	hook  func(call int) // when set, runs at the start of every call
}

func (f *fakeEngine) Assess(context.Context, normalize.Action, []byte) engine.Assessment {
	f.calls++
	if f.hook != nil {
		f.hook(f.calls)
	}
	if f.later != nil && f.calls > 1 {
		return engine.Assessment{Impact: *f.later, NamespaceLabels: map[string]string{}}
	}
	return engine.Assessment{Impact: f.imp, NamespaceLabels: map[string]string{}}
}

type fakeSnap struct {
	err       error
	taken     int
	discarded []string
	take      func(ctx context.Context) (string, error) // when set, replaces the fixed answer
	order     *[]string
}

func (f *fakeSnap) Take(ctx context.Context, _ string, _ normalize.Action, _ engine.Impact) (string, error) {
	f.taken++
	if f.order != nil {
		*f.order = append(*f.order, "snapshot")
	}
	if f.take != nil {
		return f.take(ctx)
	}
	if f.err != nil {
		return "", f.err
	}
	return "/snap", nil
}

func (f *fakeSnap) Discard(path string) { f.discarded = append(f.discarded, path) }

type fakeAudit struct {
	mu    sync.Mutex
	rows  []store.AuditRow
	err   error
	order *[]string
}

// AppendAudit fails on a cancelled ctx, as database/sql does: the gate
// must record decisions for clients that have already gone away.
func (f *fakeAudit) AppendAudit(ctx context.Context, r store.AuditRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.err != nil {
		return f.err
	}
	if f.order != nil {
		*f.order = append(*f.order, "audit")
	}
	f.rows = append(f.rows, r)
	return nil
}

type fakeApprovals struct {
	mu       sync.Mutex
	outcomes []approval.Outcome // returned by successive Verify calls; last repeats
	created  []store.Approval
	status   map[string]string
	checks   [][]string // session, human, agent, requestDigest, impactDigest per Verify
	checkErr error
	makeErr  error

	consumed   int
	consumeErr error
	order      *[]string
}

func (f *fakeApprovals) Consume(context.Context, store.Approval) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.order != nil {
		*f.order = append(*f.order, "consume")
	}
	if f.consumeErr != nil {
		return f.consumeErr
	}
	f.consumed++
	return nil
}

func (f *fakeApprovals) Verify(_ context.Context, session, human, agent, requestDigest, impactDigest string) (approval.Outcome, store.Approval, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks = append(f.checks, []string{session, human, agent, requestDigest, impactDigest})
	if f.checkErr != nil {
		return approval.None, store.Approval{}, f.checkErr
	}
	o := f.outcomes[0]
	if len(f.outcomes) > 1 {
		f.outcomes = f.outcomes[1:]
	}
	return o, store.Approval{ID: "existing0000000000000000000000000"}, nil
}
func (f *fakeApprovals) CreatePending(_ context.Context, a store.Approval) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.makeErr != nil {
		return f.makeErr
	}
	f.created = append(f.created, a)
	if f.status == nil {
		f.status = map[string]string{}
	}
	f.status[a.ID] = "pending"
	return nil
}
func (f *fakeApprovals) Status(_ context.Context, id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status[id], nil
}
func (f *fakeApprovals) set(id, st string) { f.mu.Lock(); f.status[id] = st; f.mu.Unlock() }

var alice = store.Session{ID: "s1", Human: "alice", Agent: "coding-agent"}

func newGate(imp engine.Impact, ap *fakeApprovals) (*Gate, *fakeEngine, *fakeSnap, *fakeAudit) {
	fe, fs, fa := &fakeEngine{imp: imp}, &fakeSnap{}, &fakeAudit{}
	if ap == nil {
		ap = &fakeApprovals{outcomes: []approval.Outcome{approval.None}}
	}
	return &Gate{Engine: fe, Policy: policy.Default(), Approvals: ap, Audit: fa, Snapshots: fs,
		Hold: 200 * time.Millisecond, Poll: 10 * time.Millisecond, Now: time.Now,
		Log: slog.New(slog.NewJSONHandler(io.Discard, nil))}, fe, fs, fa
}

func req(method, target string) *http.Request { return httptest.NewRequest(method, target, nil) }

func TestReadsForwardWithoutScoring(t *testing.T) {
	g, fe, _, _ := newGate(engine.Impact{}, nil)
	v := g.Decide(context.Background(), alice, req("GET", "/api/v1/namespaces/demo/pods"), nil)
	if !v.Forward || fe.calls != 0 {
		t.Errorf("verdict %+v, engine calls %d", v, fe.calls)
	}
}

func TestSafeDeleteForwardsAndAuditsDecision(t *testing.T) {
	g, _, _, fa := newGate(engine.Impact{Class: engine.ClassReversible, Measured: true}, nil)
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/pods/web-1"), nil)
	if !v.Forward {
		t.Fatalf("verdict %+v", v)
	}
	if len(fa.rows) != 1 || fa.rows[0].Kind != "decision" || fa.rows[0].Decision != "allow" || fa.rows[0].Rule != "safe" {
		t.Errorf("audit %+v", fa.rows)
	}
}

func TestHeldRequestTimesOutWithATicket(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.None}}
	g, _, fs, _ := newGate(engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1}, ap)
	start := time.Now()
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || v.Code != 403 || v.Ticket == "" || len(ap.created) != 1 || ap.created[0].ID != v.Ticket {
		t.Fatalf("verdict %+v created %+v", v, ap.created)
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Error("did not wait the hold window")
	}
	if !strings.Contains(v.Message, v.Ticket) || !strings.Contains(v.Message, "data-destruction") || strings.Contains(v.Message, "data\"") {
		t.Errorf("message %q", v.Message)
	}
	if fs.taken != 0 {
		t.Error("snapshotted a request that was not forwarded")
	}
}

func TestApprovalInsideTheWindowReleasesInline(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.None, approval.Verified}}
	g, fe, fs, _ := newGate(engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1}, ap)
	g.Hold = 2 * time.Second
	go func() {
		for {
			time.Sleep(20 * time.Millisecond)
			ap.mu.Lock()
			n := len(ap.created)
			ap.mu.Unlock()
			if n == 1 {
				ap.set(ap.created[0].ID, "approved")
				return
			}
		}
	}()
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if !v.Forward || fs.taken != 1 || fe.calls != 2 {
		t.Errorf("verdict %+v, snapshots %d, engine calls %d", v, fs.taken, fe.calls)
	}
}

func TestReleasedRetryForwards(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.Verified}}
	g, fe, _, fa := newGate(engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1}, ap)
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if !v.Forward || fe.calls != 1 || fa.rows[0].ApprovalID == "" {
		t.Errorf("verdict %+v, engine calls %d, audit %+v", v, fe.calls, fa.rows)
	}
}

func TestVoidApprovalCreatesANewOneAndSaysWhy(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.Void}}
	g, _, _, _ := newGate(engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1}, ap)
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || len(ap.created) != 1 || !strings.Contains(v.Message, "changed") {
		t.Errorf("verdict %+v", v)
	}
}

func TestDeniedIsRefusedWithoutWaiting(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.Denied}}
	g, _, _, _ := newGate(engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1}, ap)
	g.Hold = 5 * time.Second
	start := time.Now()
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || v.Code != 403 || time.Since(start) > time.Second {
		t.Errorf("verdict %+v after %v", v, time.Since(start))
	}
}

func TestClientLeavingEndsTheWait(t *testing.T) {
	g, _, _, _ := newGate(engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1}, nil)
	g.Hold = 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	v := g.Decide(ctx, alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if time.Since(start) > 2*time.Second {
		t.Error("kept waiting after the client left")
	}
	if v.Forward || v.Code != 403 || v.Ticket == "" {
		t.Errorf("verdict %+v", v)
	}
}

func TestSnapshotFailureRefusesToForward(t *testing.T) {
	g, _, fs, _ := newGate(engine.Impact{Class: engine.ClassReversible, Measured: true}, nil)
	fs.err = errors.New("disk full")
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/pods/web-1"), nil)
	if v.Forward || v.Code != 503 {
		t.Errorf("verdict %+v", v)
	}
}

func TestAuditFailureRefusesToForwardAWrite(t *testing.T) {
	g, _, _, fa := newGate(engine.Impact{Class: engine.ClassReversible, Measured: true}, nil)
	fa.err = errors.New("locked")
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/pods/web-1"), nil)
	if v.Forward || v.Code != 503 {
		t.Errorf("verdict %+v", v)
	}
}

func TestUnparseableIsRefused(t *testing.T) {
	g, _, _, _ := newGate(engine.Impact{}, nil)
	v := g.Decide(context.Background(), alice, req("POST", "/version"), nil)
	if v.Forward || v.Code != 403 {
		t.Errorf("verdict %+v", v)
	}
}

func TestCompleteAppendsAResultRowForReadsToo(t *testing.T) {
	g, _, _, fa := newGate(engine.Impact{}, nil)
	v := g.Decide(context.Background(), alice, req("GET", "/api/v1/namespaces/demo/pods"), nil)
	g.Complete(context.Background(), v, 200, "", 3*time.Millisecond)
	if len(fa.rows) != 1 || fa.rows[0].Kind != "result" || fa.rows[0].Status != 200 {
		t.Errorf("audit %+v", fa.rows)
	}
}

// A read is not scored, but it is known to be a read: its row says READ,
// measured, as the engine's own read case would. Left empty, the UI's
// fail-closed badge painted every allowed get red as UNMEASURED, a READ
// filter found nothing, and the export recorded "" (P2-R29, I3). The
// impact and labels stay empty: nothing was assessed to put in them.
func TestReadRowsAreRecordedAsRead(t *testing.T) {
	g, fe, _, fa := newGate(engine.Impact{}, nil)
	v := g.Decide(context.Background(), alice, req("GET", "/api/v1/namespaces/demo/pods"), nil)
	g.Complete(context.Background(), v, 200, "", time.Millisecond)
	if fe.calls != 0 || len(fa.rows) != 1 {
		t.Fatalf("engine calls %d, audit %+v", fe.calls, fa.rows)
	}
	r := fa.rows[0]
	if r.Class != engine.ClassRead || !r.Measured || r.Rule != "read" || r.Decision != "allow" {
		t.Errorf("read row: class %q measured %v rule %q decision %q", r.Class, r.Measured, r.Rule, r.Decision)
	}
	if r.ImpactJSON != nil || r.LabelsJSON != nil {
		t.Errorf("a read that was never scored carries impact %s labels %s", r.ImpactJSON, r.LabelsJSON)
	}
	// Refused before anything is known: still no class, which the UI
	// shows as UNMEASURED.
	if u := g.Decide(context.Background(), alice, req("POST", "/version"), nil); u.Forward {
		t.Fatal("an unparseable request was forwarded")
	}
	if last := fa.rows[len(fa.rows)-1]; last.Rule != "unparseable" || last.Class != "" || last.Measured {
		t.Errorf("unparseable row: rule %q class %q measured %v", last.Rule, last.Class, last.Measured)
	}
}

func TestMessagesCarryNoObjectOrSessionData(t *testing.T) {
	g, _, _, _ := newGate(engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1,
		EndpointsLeft: map[string]int{"svc-name-xyz": 0}}, nil)
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/secret-ns/persistentvolumeclaims/secret-claim"), nil)
	for _, leak := range []string{"secret-ns", "secret-claim", "svc-name-xyz", "alice", "s1"} {
		if strings.Contains(v.Message, leak) {
			t.Errorf("message %q contains %q", v.Message, leak)
		}
	}
}

var terminal = engine.Impact{Class: engine.ClassTerminal, Measured: true, DataDestroyed: 1}

// approveWhenCreated approves (or denies) the first pending approval as
// soon as the gate creates it, the way a human at the CLI would.
func approveWhenCreated(ap *fakeApprovals, status string) {
	go func() {
		for {
			time.Sleep(10 * time.Millisecond)
			ap.mu.Lock()
			var id string
			if len(ap.created) >= 1 {
				id = ap.created[0].ID
			}
			ap.mu.Unlock()
			if id != "" {
				ap.set(id, status)
				return
			}
		}
	}()
}

func TestCheckIsAskedWithTheAuthenticatedSession(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.Verified}}
	g, _, _, _ := newGate(terminal, ap)
	r := req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data")
	r.Header.Set("Impersonate-User", "mallory")
	g.Decide(context.Background(), alice, r, nil)
	if len(ap.checks) != 1 {
		t.Fatalf("checks %v", ap.checks)
	}
	c := ap.checks[0]
	if c[0] != "s1" || c[1] != "alice" || c[2] != "coding-agent" || c[3] == "" || c[4] != terminal.Digest() {
		t.Errorf("check args %v", c)
	}
}

func TestPendingApprovalCarriesTheSessionAndMeasurement(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.None}}
	g, _, _, _ := newGate(terminal, ap)
	g.Hold = 0
	g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if len(ap.created) != 1 {
		t.Fatalf("created %+v", ap.created)
	}
	a := ap.created[0]
	if a.Session != "s1" || a.Human != "alice" || a.Agent != "coding-agent" || a.Status != "pending" ||
		a.Rule != "data-destruction" || a.ImpactDigest != terminal.Digest() || a.RequestDigest == "" ||
		len(a.ActionJSON) == 0 || len(a.ImpactJSON) == 0 || len(a.ID) != 32 {
		t.Errorf("pending %+v", a)
	}
}

func TestHeldDecisionIsAuditedAsAHold(t *testing.T) {
	g, _, _, fa := newGate(terminal, nil)
	g.Hold = 0
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if len(fa.rows) != 1 {
		t.Fatalf("audit %+v", fa.rows)
	}
	r := fa.rows[0]
	if r.Kind != "decision" || r.Decision != "hold" || r.Rule != "data-destruction" || r.ApprovalID != v.Ticket ||
		r.Session != "s1" || r.Human != "alice" || r.Agent != "coding-agent" || r.Resource != "persistentvolumeclaims" ||
		r.Name != "data" || r.Class != engine.ClassTerminal || !r.Measured || r.Snapshot != "" ||
		string(r.LabelsJSON) != "{}" || len(r.ImpactJSON) == 0 || len(r.ActionJSON) == 0 || len(r.RequestID) != 32 {
		t.Errorf("row %+v", r)
	}
}

func TestInlineReleaseRescoresAndRefusesAChangedImpact(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.None, approval.Void}}
	g, fe, fs, _ := newGate(terminal, ap)
	changed := terminal
	changed.DataDestroyed = 2
	fe.later = &changed
	g.Hold = 2 * time.Second
	approveWhenCreated(ap, "approved")
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || fs.taken != 0 || fe.calls != 2 {
		t.Fatalf("verdict %+v, snapshots %d, engine calls %d", v, fs.taken, fe.calls)
	}
	if len(ap.checks) != 2 || ap.checks[1][4] != changed.Digest() {
		t.Errorf("second check did not use the fresh measurement: %v", ap.checks)
	}
	if len(ap.created) != 2 || v.Ticket != ap.created[1].ID || ap.created[1].ImpactDigest != changed.Digest() ||
		!strings.Contains(v.Message, "changed") {
		t.Errorf("verdict %+v created %+v", v, ap.created)
	}
}

func TestDenialInsideTheWindowRefuses(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.None}}
	g, _, fs, _ := newGate(terminal, ap)
	g.Hold = 2 * time.Second
	approveWhenCreated(ap, "denied")
	start := time.Now()
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || v.Code != 403 || v.Ticket != "" || !strings.Contains(v.Message, "denied") || fs.taken != 0 {
		t.Errorf("verdict %+v", v)
	}
	if time.Since(start) > time.Second {
		t.Error("kept waiting after the denial")
	}
}

func TestPolicyDenyRefusesWithoutAnApproval(t *testing.T) {
	p, err := policy.Load([]byte("rules:\n  - name: no-secrets\n    when: action.resource == \"secrets\"\n    then: deny\ndefault: hold\nunmeasured: hold\n"))
	if err != nil {
		t.Fatal(err)
	}
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.None}}
	g, _, fs, fa := newGate(engine.Impact{Class: engine.ClassReversible, Measured: true}, ap)
	g.Policy = p
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/secrets/token"), nil)
	if v.Forward || v.Code != 403 || v.Message != "blastgate: refused by policy rule no-secrets" || fs.taken != 0 ||
		len(ap.checks) != 0 || len(fa.rows) != 1 || fa.rows[0].Decision != "deny" {
		t.Errorf("verdict %+v audit %+v", v, fa.rows)
	}
}

func TestUnparseableIsAuditedAsADeny(t *testing.T) {
	g, fe, _, fa := newGate(engine.Impact{}, nil)
	g.Decide(context.Background(), alice, req("POST", "/version"), nil)
	if fe.calls != 0 || len(fa.rows) != 1 || fa.rows[0].Decision != "deny" || fa.rows[0].Rule != "unparseable" || fa.rows[0].Session != "s1" {
		t.Errorf("audit %+v", fa.rows)
	}
}

func TestClientLeavingMidHoldStillRecordsTheHold(t *testing.T) {
	g, _, _, fa := newGate(terminal, nil)
	g.Hold = 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	v := g.Decide(ctx, alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	g.Complete(ctx, v, v.Code, "", time.Millisecond)
	if len(fa.rows) != 2 || fa.rows[0].Kind != "decision" || fa.rows[0].Decision != "hold" || fa.rows[0].ApprovalID != v.Ticket ||
		fa.rows[1].Kind != "result" || fa.rows[1].Status != 403 {
		t.Errorf("audit %+v", fa.rows)
	}
}

func TestInlineReleaseHonoursAPolicyDenyOnTheFreshMeasurement(t *testing.T) {
	p, err := policy.Load([]byte("rules:\n  - name: too-much\n    when: impact.dataDestroyed > 1\n    then: deny\n  - name: some\n    when: impact.dataDestroyed > 0\n    then: hold\ndefault: hold\nunmeasured: hold\n"))
	if err != nil {
		t.Fatal(err)
	}
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.None, approval.Verified}}
	g, fe, fs, fa := newGate(terminal, ap)
	g.Policy = p
	worse := terminal
	worse.DataDestroyed = 2
	fe.later = &worse
	g.Hold = 2 * time.Second
	approveWhenCreated(ap, "approved")
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || v.Code != 403 || v.Message != "blastgate: refused by policy rule too-much" || fs.taken != 0 || len(ap.checks) != 1 {
		t.Errorf("verdict %+v, snapshots %d, checks %v", v, fs.taken, ap.checks)
	}
	if len(fa.rows) != 1 || fa.rows[0].Decision != "deny" || fa.rows[0].Rule != "too-much" {
		t.Errorf("audit %+v", fa.rows)
	}
}

func TestInlineReleaseOfAGoneApprovalTicketsANewOne(t *testing.T) {
	// Approved, but a concurrent identical request spent it first: the
	// recheck's Check finds nothing usable.
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.None, approval.None}}
	g, _, fs, _ := newGate(terminal, ap)
	g.Hold = 2 * time.Second
	approveWhenCreated(ap, "approved")
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || fs.taken != 0 || len(ap.created) != 2 || v.Ticket != ap.created[1].ID || strings.Contains(v.Message, ap.created[0].ID) {
		t.Errorf("verdict %+v created %+v", v, ap.created)
	}
}

func TestClientLeavingDuringTheRescoreSpendsNothing(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.None, approval.Verified}}
	g, fe, fs, _ := newGate(terminal, ap)
	g.Hold = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fe.hook = func(call int) {
		if call == 2 {
			cancel()
		}
	}
	approveWhenCreated(ap, "approved")
	v := g.Decide(ctx, alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || fs.taken != 0 || len(ap.checks) != 1 || len(ap.created) != 1 || v.Ticket != ap.created[0].ID {
		t.Errorf("verdict %+v, checks %v, created %+v", v, ap.checks, ap.created)
	}
}

func TestApprovalCheckFailureRefuses(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.Verified}, checkErr: errors.New("db locked")}
	g, _, fs, _ := newGate(terminal, ap)
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || v.Code != 503 || fs.taken != 0 || strings.Contains(v.Message, "locked") {
		t.Errorf("verdict %+v", v)
	}
}

func TestCreatePendingFailureRefuses(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.None}, makeErr: errors.New("disk full")}
	g, _, fs, _ := newGate(terminal, ap)
	start := time.Now()
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || v.Code != 503 || v.Ticket != "" || fs.taken != 0 || strings.Contains(v.Message, "disk") {
		t.Errorf("verdict %+v", v)
	}
	if time.Since(start) > 150*time.Millisecond {
		t.Error("waited on an approval that was never created")
	}
}

// Final review I2(a): the approval is spent after the snapshot and the
// decision row, never before -- a failure in either leaves it for the
// agent's next retry.
func TestApprovalIsSpentOnlyAfterSnapshotAndAudit(t *testing.T) {
	var order []string
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.Verified}, order: &order}
	g, _, fs, fa := newGate(terminal, ap)
	fs.order, fa.order = &order, &order
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if !v.Forward || strings.Join(order, ",") != "snapshot,audit,consume" {
		t.Errorf("verdict %+v, order %v", v, order)
	}
}

func TestFailedSnapshotLeavesTheApprovalUnspent(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.Verified}}
	g, _, fs, _ := newGate(terminal, ap)
	fs.err = errors.New("sounding refused")
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || v.Code != 503 || ap.consumed != 0 {
		t.Fatalf("verdict %+v, consumed %d", v, ap.consumed)
	}
	fs.err = nil
	v = g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if !v.Forward || ap.consumed != 1 {
		t.Errorf("retry after the snapshot recovered: verdict %+v, consumed %d", v, ap.consumed)
	}
}

func TestFailedDecisionAuditLeavesTheApprovalUnspent(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.Verified}}
	g, _, fs, fa := newGate(terminal, ap)
	fa.err = errors.New("locked")
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || ap.consumed != 0 || len(fs.discarded) != 1 {
		t.Errorf("verdict %+v, consumed %d, discarded %v", v, ap.consumed, fs.discarded)
	}
}

// A retry that verified but lost the consume to a concurrent one is not
// forwarded, and its snapshot is not left to look like a write's undo.
func TestLostConsumeRefusesAndDiscardsTheSnapshot(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.Verified}, consumeErr: store.ErrConflict}
	g, _, fs, fa := newGate(terminal, ap)
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || v.Code != http.StatusConflict || len(fs.discarded) != 1 || fs.discarded[0] != "/snap" {
		t.Errorf("verdict %+v, discarded %v", v, fs.discarded)
	}
	if len(fa.rows) != 1 {
		t.Errorf("want exactly one decision row, got %+v", fa.rows)
	}
	ap.consumeErr = errors.New("disk I/O error")
	v = g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || v.Code != 503 || strings.Contains(v.Message, "disk") {
		t.Errorf("verdict %+v", v)
	}
}

// Final review I2(d): a snapshot that hangs is cut off at its budget and
// the write refused; one that returns late is discarded, not trusted.
func TestSnapshotIsBoundedByItsBudget(t *testing.T) {
	ap := &fakeApprovals{outcomes: []approval.Outcome{approval.Verified}}
	g, _, fs, _ := newGate(terminal, ap)
	g.SnapshotBudget = 50 * time.Millisecond
	fs.take = func(ctx context.Context) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	start := time.Now()
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || v.Code != 503 || ap.consumed != 0 || time.Since(start) > time.Second {
		t.Errorf("verdict %+v, consumed %d, after %v", v, ap.consumed, time.Since(start))
	}
	fs.take = func(ctx context.Context) (string, error) {
		time.Sleep(100 * time.Millisecond) // ignores ctx, then claims success
		return "/late", nil
	}
	v = g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	if v.Forward || ap.consumed != 0 || len(fs.discarded) != 1 || fs.discarded[0] != "/late" {
		t.Errorf("verdict %+v, consumed %d, discarded %v", v, ap.consumed, fs.discarded)
	}
}

// Final review I4: the ticket speaks to a person, not to the agent that
// reads it.
func TestTicketAsksForAPerson(t *testing.T) {
	g, _, _, _ := newGate(terminal, nil)
	g.Hold = 0
	v := g.Decide(context.Background(), alice, req("DELETE", "/api/v1/namespaces/demo/persistentvolumeclaims/data"), nil)
	want := "blastgate: held for approval " + v.Ticket + " (rule data-destruction: " + terminal.Summary() +
		"). Ask a person to approve it with `blastgate approve " + v.Ticket + " --by <name>`, then retry."
	if v.Message != want {
		t.Errorf("message\n%q\nwant\n%q", v.Message, want)
	}
}

// Final review I5: a GET that upgrades the connection is scored and put
// to policy, never passed through as a read.
func TestUpgradeGETIsScoredNotPassed(t *testing.T) {
	g, fe, _, _ := newGate(engine.Unmeasured("a stream"), nil)
	g.Hold = 0
	r := req("GET", "/apis/subresources.kubevirt.io/v1/namespaces/demo/virtualmachineinstances/vm/vnc")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	v := g.Decide(context.Background(), alice, r, nil)
	if v.Forward || fe.calls != 1 || v.Ticket == "" {
		t.Errorf("verdict %+v, engine calls %d", v, fe.calls)
	}
}
