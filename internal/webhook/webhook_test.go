package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/SaiPisey2/blastgate/internal/store"
)

type fakeRec struct {
	mu   sync.Mutex
	rows []store.BypassRow
	err  error
}

func (f *fakeRec) AppendBypass(_ context.Context, b store.BypassRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.rows = append(f.rows, b)
	return nil
}

func (f *fakeRec) got() []store.BypassRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.BypassRow(nil), f.rows...)
}

var t0 = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func newHandler(rec Recorder) *Handler {
	return &Handler{Rec: rec, Ignore: DefaultIgnore, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return t0 }}
}

// logged returns a handler whose log lines land in the returned buffer.
func logged(rec Recorder) (*Handler, *syncBuf) {
	h := newHandler(rec)
	b := &syncBuf{}
	h.Log = slog.New(slog.NewTextHandler(b, nil))
	return h, b
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func review(uid, user string, extra map[string]authenticationv1.ExtraValue) []byte {
	dry := false
	ar := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:         types.UID(uid),
			Operation:   admissionv1.Delete,
			Resource:    metav1.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
			Namespace:   "demo",
			Name:        "web",
			UserInfo:    authenticationv1.UserInfo{Username: user, Groups: []string{"system:authenticated"}, Extra: extra},
			DryRun:      &dry,
			SubResource: "",
		},
	}
	b, err := json.Marshal(ar)
	if err != nil {
		panic(err)
	}
	return b
}

func post(t *testing.T, h http.Handler, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body)))
	return w
}

// allowed decodes the response and fails the test unless it is an
// allowing AdmissionReview for uid.
func allowed(t *testing.T, w *httptest.ResponseRecorder, uid string) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", w.Code, w.Body.String())
	}
	var ar admissionv1.AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &ar); err != nil {
		t.Fatalf("response is not an AdmissionReview: %v", err)
	}
	if ar.APIVersion != "admission.k8s.io/v1" || ar.Kind != "AdmissionReview" {
		t.Errorf("type = %s/%s", ar.APIVersion, ar.Kind)
	}
	if ar.Response == nil || !ar.Response.Allowed || string(ar.Response.UID) != uid {
		t.Errorf("response = %+v, want allowed with uid %q", ar.Response, uid)
	}
}

func TestAlwaysAllowsAndEchoesUID(t *testing.T) {
	h := newHandler(&fakeRec{})
	allowed(t, post(t, h, review("u-bypass", "alice", nil)), "u-bypass")
	allowed(t, post(t, h, review("u-through", "alice", map[string]authenticationv1.ExtraValue{"blastgate-session": {"s1"}})), "u-through")
	allowed(t, post(t, h, review("u-ctrl", "system:node:kind-control-plane", nil)), "u-ctrl")
}

func TestRecordsWritesThatBypassedBlastgate(t *testing.T) {
	rec := &fakeRec{}
	allowed(t, post(t, newHandler(rec), review("u-1", "alice", nil)), "u-1")
	rows := rec.got()
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.User != "alice" || r.Verb != "delete" || r.Group != "apps" || r.Resource != "deployments" ||
		r.Namespace != "demo" || r.Name != "web" || r.UID != "u-1" || !r.At.Equal(t0) ||
		len(r.Groups) != 1 || r.Groups[0] != "system:authenticated" || r.DryRun {
		t.Errorf("row = %+v", r)
	}
}

func TestWritesThroughBlastgateAreNotRecorded(t *testing.T) {
	rec := &fakeRec{}
	allowed(t, post(t, newHandler(rec), review("u-1", "alice", map[string]authenticationv1.ExtraValue{"blastgate-session": {"s1"}})), "u-1")
	if n := len(rec.got()); n != 0 {
		t.Errorf("rows = %d, want 0", n)
	}
	// An empty value is not a session: it is what a hand-written
	// impersonation header with no content produces.
	allowed(t, post(t, newHandler(rec), review("u-2", "alice", map[string]authenticationv1.ExtraValue{"blastgate-session": {""}})), "u-2")
	if n := len(rec.got()); n != 1 {
		t.Errorf("rows = %d after an empty session value, want 1", n)
	}
}

func TestControllersAreIgnoredAgentsAreNot(t *testing.T) {
	rec := &fakeRec{}
	h := newHandler(rec)
	for _, u := range []string{"system:serviceaccount:kube-system:replicaset-controller", "system:node:kind-control-plane"} {
		allowed(t, post(t, h, review("u-"+u, u, nil)), "u-"+u)
	}
	if n := len(rec.got()); n != 0 {
		t.Fatalf("controllers recorded: %+v", rec.got())
	}
	allowed(t, post(t, h, review("u-agent", "system:serviceaccount:demo:agent-sa", nil)), "u-agent")
	rows := rec.got()
	if len(rows) != 1 || rows[0].User != "system:serviceaccount:demo:agent-sa" {
		t.Errorf("agent service account not recorded: %+v", rows)
	}
}

func TestIgnoredIsAPrefixMatchOnly(t *testing.T) {
	// "system:kube-" must not swallow a service account in a namespace
	// that merely starts with "kube-": that is the agent's namespace, not
	// the control plane.
	if Ignored("system:serviceaccount:kube-public-agent:sa", DefaultIgnore) {
		t.Error("a non-kube-system service account was ignored")
	}
	if !Ignored("system:kube-scheduler", DefaultIgnore) || !Ignored("system:apiserver", DefaultIgnore) {
		t.Error("control-plane identities not ignored")
	}
	if Ignored("alice", nil) {
		t.Error("no prefixes ignored someone")
	}
}

func TestWebhookBodyLimit(t *testing.T) {
	rec := &fakeRec{}
	body := review("u-big", "alice", nil)
	// Pad inside a valid JSON document so only the size can be the reason.
	big := append([]byte(`{"pad":"`+strings.Repeat("x", 9<<20)+`",`), body[1:]...)
	h, logs := logged(rec)
	w := post(t, h, big)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", w.Code)
	}
	if n := len(rec.got()); n != 0 {
		t.Errorf("rows = %d, want 0", n)
	}
	if l := logs.String(); !strings.Contains(l, "too large") || strings.Contains(l, "xxxx") {
		t.Errorf("413 must be logged without the body: %q", l)
	}
}

func TestAnUpdateCarryingTwoLargeObjectsIsObserved(t *testing.T) {
	// The API server caps a client body at 3 MiB, but an UPDATE review
	// carries object and oldObject: over 3 MiB here is legitimate, and
	// dropping it would let a padded object escape the record.
	rec := &fakeRec{}
	var ar admissionv1.AdmissionReview
	_ = json.Unmarshal(review("u-upd", "alice", nil), &ar)
	obj := []byte(`{"data":"` + strings.Repeat("y", 3<<20-100) + `"}`)
	ar.Request.Operation = admissionv1.Update
	ar.Request.Object.Raw, ar.Request.OldObject.Raw = obj, obj
	b, _ := json.Marshal(ar)
	if len(b) <= 6<<20 {
		t.Fatalf("review is only %d bytes", len(b))
	}
	allowed(t, post(t, newHandler(rec), b), "u-upd")
	if n := len(rec.got()); n != 1 {
		t.Errorf("rows = %d, want 1", n)
	}
}

// blockingRec holds every AppendBypass until release is closed.
type blockingRec struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingRec) AppendBypass(ctx context.Context, _ store.BypassRow) error {
	select {
	case b.started <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return nil
}

func TestAFloodIsAnsweredBusyNotQueued(t *testing.T) {
	rec := &blockingRec{started: make(chan struct{}, maxInFlight), release: make(chan struct{})}
	h, logs := logged(rec)
	var wg sync.WaitGroup
	codes := make([]int, maxInFlight)
	for i := range maxInFlight {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = post(t, h, review("u-held", "alice", nil)).Code
		}()
	}
	for range maxInFlight {
		<-rec.started
	}
	if w := post(t, h, review("u-over", "alice", nil)); w.Code != http.StatusServiceUnavailable {
		t.Errorf("request over the bound: status = %d, want 503", w.Code)
	}
	if !strings.Contains(logs.String(), "busy") {
		t.Errorf("503 not logged: %q", logs.String())
	}
	close(rec.release)
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("held request %d: status = %d", i, c)
		}
	}
	// The slots come back: the next review is handled again.
	rec2 := &fakeRec{}
	h.Rec = rec2
	allowed(t, post(t, h, review("u-after", "alice", nil)), "u-after")
}

func TestNoRecorderStillAllows(t *testing.T) {
	h, logs := logged(nil)
	allowed(t, post(t, h, review("u-1", "alice", nil)), "u-1")
	if !strings.Contains(logs.String(), "no recorder") {
		t.Errorf("missing recorder not logged: %q", logs.String())
	}
}

func TestRecordingFailureStillAllows(t *testing.T) {
	rec := &fakeRec{err: errors.New("disk full")}
	allowed(t, post(t, newHandler(rec), review("u-1", "alice", nil)), "u-1")
}

func TestReadsAreNotRecorded(t *testing.T) {
	// The configuration registers writes only, but a hand-edited rule
	// could send anything; a read is allowed and not recorded.
	rec := &fakeRec{}
	var ar admissionv1.AdmissionReview
	_ = json.Unmarshal(review("u-1", "alice", nil), &ar)
	ar.Request.Operation = "GET"
	b, _ := json.Marshal(ar)
	allowed(t, post(t, newHandler(rec), b), "u-1")
	if n := len(rec.got()); n != 0 {
		t.Errorf("rows = %d, want 0", n)
	}
}

func TestNotAReviewIs400AndOnlyPostValidate(t *testing.T) {
	h := newHandler(&fakeRec{})
	if w := post(t, h, []byte("not json")); w.Code != http.StatusBadRequest {
		t.Errorf("garbage: status = %d, want 400", w.Code)
	}
	if w := post(t, h, []byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`)); w.Code != http.StatusBadRequest {
		t.Errorf("no request: status = %d, want 400", w.Code)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/validate", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status = %d, want 405", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/other", bytes.NewReader(review("u", "alice", nil))))
	if w.Code != http.StatusNotFound {
		t.Errorf("other path: status = %d, want 404", w.Code)
	}
}

func TestAMalformedRequestWithAUIDIsStillAllowed(t *testing.T) {
	// A field of the wrong type fails the typed decode, but the uid is
	// readable: answer allowed so the API server does not log an error.
	body := []byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"u-odd","operation":7}}`)
	rec := &fakeRec{}
	h, logs := logged(rec)
	allowed(t, post(t, h, body), "u-odd")
	if n := len(rec.got()); n != 0 {
		t.Errorf("rows = %d, want 0", n)
	}
	if l := logs.String(); !strings.Contains(l, "level=WARN") || !strings.Contains(l, "u-odd") {
		t.Errorf("undecodable review not logged with its uid: %q", l)
	}
}

// reviewOf is review for another operation and resource.
func reviewOf(uid, user string, op admissionv1.Operation, group, resource string) []byte {
	var ar admissionv1.AdmissionReview
	if err := json.Unmarshal(review(uid, user, nil), &ar); err != nil {
		panic(err)
	}
	ar.Request.Operation = op
	ar.Request.Resource = metav1.GroupVersionResource{Group: group, Version: "v1", Resource: resource}
	b, _ := json.Marshal(ar)
	return b
}

// TestLeaseAndEventNoiseIsSkipped: controllers outside kube-system
// (cert-manager, ingress-nginx, operators) renew a Lease every few seconds
// and write Events all day. Recorded, they are tens of thousands of rows
// a day in a table that is never pruned, and the bypass page shows
// nothing else. They are skipped unless IncludeNoise asks for them
// (P2-R29, I6). The match is exact: another group's "leases" is recorded,
// and so is a delete of a Lease or an Event.
func TestLeaseAndEventNoiseIsSkipped(t *testing.T) {
	const sa = "system:serviceaccount:cert-manager:cert-manager"
	noise := [][]byte{
		reviewOf("u-lease", sa, admissionv1.Update, "coordination.k8s.io", "leases"),
		reviewOf("u-lease-new", sa, admissionv1.Create, "coordination.k8s.io", "leases"),
		reviewOf("u-event", sa, admissionv1.Create, "", "events"),
		reviewOf("u-event2", sa, admissionv1.Update, "events.k8s.io", "events"),
	}
	signal := [][]byte{
		reviewOf("u-cm", sa, admissionv1.Create, "", "configmaps"),
		reviewOf("u-other-leases", sa, admissionv1.Update, "example.com", "leases"),
		reviewOf("u-other-events", sa, admissionv1.Create, "example.com", "events"),
		reviewOf("u-lease-delete", sa, admissionv1.Delete, "coordination.k8s.io", "leases"),
		reviewOf("u-event-delete", sa, admissionv1.Delete, "events.k8s.io", "events"),
	}
	uids := func(rows []store.BypassRow) string {
		var s []string
		for _, r := range rows {
			s = append(s, r.UID)
		}
		return strings.Join(s, ",")
	}

	rec := &fakeRec{}
	h := newHandler(rec)
	for _, b := range append(append([][]byte{}, noise...), signal...) {
		if w := post(t, h, b); w.Code != 200 || !strings.Contains(w.Body.String(), `"allowed":true`) {
			t.Fatalf("not allowed: %d %s", w.Code, w.Body.String())
		}
	}
	if got := uids(rec.got()); got != "u-cm,u-other-leases,u-other-events,u-lease-delete,u-event-delete" {
		t.Errorf("recorded %s, want only the non-noise writes", got)
	}

	rec = &fakeRec{}
	h = newHandler(rec)
	h.IncludeNoise = true
	for _, b := range noise {
		post(t, h, b)
	}
	if got := uids(rec.got()); got != "u-lease,u-lease-new,u-event,u-event2" {
		t.Errorf("with IncludeNoise recorded %s, want every lease and event write", got)
	}
}
