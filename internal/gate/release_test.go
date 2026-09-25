package gate

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SaiPisey2/blastgate/internal/approval"
	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/policy"
	"github.com/SaiPisey2/blastgate/internal/snapshot"
	"github.com/SaiPisey2/blastgate/internal/store"
	"github.com/SaiPisey2/blastgate/internal/upstream"
)

// These tests run the release path with the real approval service, store
// and snapshot taker; only the scoring and the API server are stand-ins.
// Final review I2: the approval must survive a snapshot that fails, and
// the writes the gate could not measure must still be snapshottable once
// approved.

type realRelease struct {
	g       *Gate
	svc     *approval.Service
	st      *store.Store
	snapDir string
	gets    atomic.Int32
}

// newRealRelease wires a gate whose API server answers GETs with answer.
func newRealRelease(t *testing.T, answer func(n int32, w http.ResponseWriter, r *http.Request)) *realRelease {
	t.Helper()
	rr := &realRelease{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Impersonate-User") != "alice" {
			t.Errorf("snapshot sent %s %s as %q", r.Method, r.URL.Path, r.Header.Get("Impersonate-User"))
			w.WriteHeader(http.StatusForbidden)
			return
		}
		answer(rr.gets.Add(1), w, r)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	eng := engine.New(&upstream.Upstream{URL: u, Normal: http.DefaultTransport}, time.Second)
	st, err := store.Open(filepath.Join(t.TempDir(), "bg.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rr.st = st
	rr.svc = &approval.Service{Store: st, Key: []byte("3f9a1c07d24be85f6a0913c7e2d84b5f"), TokenTTL: 15 * time.Minute, PendingTTL: time.Hour, Now: time.Now}
	rr.snapDir = filepath.Join(t.TempDir(), "snapshots")
	rr.g = &Gate{
		// The engine refuses these writes as it does live: unmeasured.
		Engine:         &fakeEngine{imp: engine.Unmeasured("not measured by this build")},
		Policy:         policy.Default(),
		Approvals:      testApprovals{svc: rr.svc, st: st},
		Audit:          st,
		Snapshots:      &snapshot.Taker{Dir: rr.snapDir, Engine: eng},
		SnapshotBudget: time.Second,
		Hold:           0,
		Now:            time.Now,
		Log:            slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	return rr
}

// testApprovals is serve's adapter, restated: gate cannot import main.
type testApprovals struct {
	svc *approval.Service
	st  *store.Store
}

func (a testApprovals) Verify(ctx context.Context, session, human, agent, rd, id string) (approval.Outcome, store.Approval, error) {
	return a.svc.Verify(ctx, session, human, agent, rd, id)
}
func (a testApprovals) Consume(ctx context.Context, ap store.Approval) error {
	return a.svc.Consume(ctx, ap)
}
func (a testApprovals) CreatePending(ctx context.Context, ap store.Approval) error {
	ap.Expires = time.Now().Add(time.Hour)
	return a.st.CreateApproval(ctx, ap)
}
func (a testApprovals) Status(ctx context.Context, id string) (string, error) {
	ap, err := a.st.ApprovalByID(ctx, id)
	return ap.Status, err
}

// holdAndApprove sends target once (held), approves the ticket as bob and
// returns its ID.
func (rr *realRelease) holdAndApprove(t *testing.T, method, target string) string {
	t.Helper()
	v := rr.g.Decide(context.Background(), alice, req(method, target), nil)
	if v.Forward || v.Ticket == "" {
		t.Fatalf("not held: %+v", v)
	}
	if _, err := rr.svc.Approve(context.Background(), v.Ticket, "bob"); err != nil {
		t.Fatal(err)
	}
	return v.Ticket
}

func (rr *realRelease) status(t *testing.T, id string) string {
	t.Helper()
	a, err := rr.st.ApprovalByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return a.Status
}

func TestApprovedClusterScopedDeleteForwardsAfterSnapshot(t *testing.T) {
	pv := `{"kind":"PersistentVolume","apiVersion":"v1","metadata":{"name":"pv-1"}}`
	rr := newRealRelease(t, func(_ int32, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/persistentvolumes/pv-1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, pv)
	})
	id := rr.holdAndApprove(t, "DELETE", "/api/v1/persistentvolumes/pv-1")
	v := rr.g.Decide(context.Background(), alice, req("DELETE", "/api/v1/persistentvolumes/pv-1"), nil)
	if !v.Forward || v.approvalID != id || v.snapshot == "" {
		t.Fatalf("approved retry: %+v", v)
	}
	if got, _ := os.ReadFile(filepath.Join(v.snapshot, "before.json")); string(got) != pv {
		t.Errorf("before.json = %s", got)
	}
	if _, err := os.Stat(filepath.Join(v.snapshot, "RESTORE.txt")); err != nil {
		t.Error(err)
	}
	if st := rr.status(t, id); st != "consumed" {
		t.Errorf("approval %s after forwarding", st)
	}
}

func TestFailedSnapshotKeepsTheApprovalForTheNextRetry(t *testing.T) {
	pv := `{"kind":"PersistentVolume","apiVersion":"v1","metadata":{"name":"pv-1"}}`
	rr := newRealRelease(t, func(n int32, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		io.WriteString(w, pv)
	})
	id := rr.holdAndApprove(t, "DELETE", "/api/v1/persistentvolumes/pv-1")
	v := rr.g.Decide(context.Background(), alice, req("DELETE", "/api/v1/persistentvolumes/pv-1"), nil)
	if v.Forward || v.Code != 503 {
		t.Fatalf("forwarded without a snapshot: %+v", v)
	}
	if st := rr.status(t, id); st != "approved" {
		t.Fatalf("a failed snapshot left the approval %s", st)
	}
	if ents, _ := os.ReadDir(rr.snapDir); len(ents) != 0 {
		t.Errorf("a failed snapshot left %d entries", len(ents))
	}
	v = rr.g.Decide(context.Background(), alice, req("DELETE", "/api/v1/persistentvolumes/pv-1"), nil)
	if !v.Forward || v.approvalID != id || rr.status(t, id) != "consumed" {
		t.Errorf("the next retry was not released: %+v", v)
	}
}

func TestApprovedDeleteCollectionWritesTheList(t *testing.T) {
	list := `{"kind":"ConfigMapList","apiVersion":"v1","items":[{"metadata":{"name":"a","labels":{"app":"web"}}}]}`
	rr := newRealRelease(t, func(_ int32, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/demo/configmaps" || r.URL.Query().Get("labelSelector") != "app=web" {
			t.Errorf("listed %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		io.WriteString(w, list)
	})
	target := "/api/v1/namespaces/demo/configmaps?labelSelector=app%3Dweb"
	id := rr.holdAndApprove(t, "DELETE", target)
	v := rr.g.Decide(context.Background(), alice, req("DELETE", target), nil)
	if !v.Forward || v.snapshot == "" || rr.status(t, id) != "consumed" {
		t.Fatalf("approved deletecollection: %+v", v)
	}
	if got, _ := os.ReadFile(filepath.Join(v.snapshot, "list.json")); string(got) != list {
		t.Errorf("list.json = %s", got)
	}
}

func TestHungSnapshotRefusesAndKeepsTheApproval(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	rr := newRealRelease(t, func(_ int32, w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	rr.g.SnapshotBudget = 100 * time.Millisecond
	id := rr.holdAndApprove(t, "DELETE", "/api/v1/persistentvolumes/pv-1")
	start := time.Now()
	v := rr.g.Decide(context.Background(), alice, req("DELETE", "/api/v1/persistentvolumes/pv-1"), nil)
	if v.Forward || v.Code != 503 || time.Since(start) > 2*time.Second {
		t.Errorf("verdict %+v after %v", v, time.Since(start))
	}
	if st := rr.status(t, id); st != "approved" {
		t.Errorf("a timed-out snapshot left the approval %s", st)
	}
}
