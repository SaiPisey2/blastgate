package snapshot

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SaiPisey2/sounding/pkg/model"

	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/normalize"
	"github.com/SaiPisey2/blastgate/internal/upstream"
)

func TestDeleteSnapshotDelegatesToSounding(t *testing.T) {
	dir := t.TempDir()
	var got model.Action
	tk := &Taker{Dir: dir, SoundingScore: func(_ context.Context, act model.Action, d string) error {
		got = act
		return os.WriteFile(filepath.Join(d, "restore.sh"), []byte("#!/bin/sh\n"), 0o600)
	}}
	a := normalize.Action{Verb: "delete", Group: "apps", Version: "v1", Resource: "deployments", Namespace: "demo", Name: "web"}
	// The brief's own example used "req-1"; the gate's request IDs are 16
	// random bytes hex (see global-constraints.md and this task's brief,
	// "Take still validates ^[0-9a-f]{32}$"), so a literal, non-hex ID is
	// swapped for a valid one here -- keeping it would test the validator
	// rejecting the ID, not the delegation this test is named for.
	out, err := tk.Take(context.Background(), "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", a, engine.Impact{Class: engine.ClassCompensable, Measured: true})
	if err != nil || out == "" {
		t.Fatalf("take = %q, %v", out, err)
	}
	if got.Target.Name != "web" || got.Target.Resource != "deployments" {
		t.Errorf("sounding got %+v", got)
	}
	st, _ := os.Stat(out)
	if st.Mode().Perm() != 0o700 {
		t.Errorf("snapshot dir mode %v", st.Mode().Perm())
	}
}

func TestReversibleDeleteTakesNothing(t *testing.T) {
	tk := &Taker{Dir: t.TempDir(), SoundingScore: func(context.Context, model.Action, string) error {
		t.Fatal("a reversible delete was snapshotted")
		return nil
	}}
	a := normalize.Action{Verb: "delete", Version: "v1", Resource: "pods", Namespace: "demo", Name: "web-1"}
	// See the note in TestDeleteSnapshotDelegatesToSounding: swapped for a
	// valid request id so this exercises the reversible-delete path, not
	// the id validator.
	if out, err := tk.Take(context.Background(), "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2", a, engine.Impact{Class: engine.ClassReversible, Measured: true}); err != nil || out != "" {
		t.Errorf("take = %q, %v", out, err)
	}
}

func TestSoundingFailureIsAnError(t *testing.T) {
	tk := &Taker{Dir: t.TempDir(), SoundingScore: func(context.Context, model.Action, string) error { return os.ErrPermission }}
	a := normalize.Action{Verb: "delete", Version: "v1", Resource: "persistentvolumeclaims", Namespace: "demo", Name: "data"}
	// A valid id, so this fails for the reason the test is named for --
	// sounding's own error -- and not because the id validator rejected
	// "r" first (see the note in TestDeleteSnapshotDelegatesToSounding).
	if _, err := tk.Take(context.Background(), "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3", a, engine.Impact{Class: engine.ClassTerminal, Measured: true}); err == nil {
		t.Error("a failed snapshot was reported as taken")
	}
}

// apiServer answers every GET with body's content, regardless of path --
// Before's own path building is exercised in the engine package; here only
// that Take writes what Before returns, and (via lastRequest) that Before
// sent it impersonated.
func apiServer(t *testing.T, body string) (*engine.Engine, func() *http.Request) {
	t.Helper()
	var last *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = r.Clone(context.Background())
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	e := engine.New(&upstream.Upstream{URL: u, Normal: http.DefaultTransport}, time.Second)
	return e, func() *http.Request { return last }
}

func TestPatchWritesBeforeObject(t *testing.T) {
	cm := `{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"cfg","namespace":"demo"},"data":{"k":"v"}}`
	e, lastRequest := apiServer(t, cm)
	tk := &Taker{Dir: t.TempDir(), Engine: e}
	a := normalize.Action{
		Verb: "patch", Version: "v1", Resource: "configmaps", Namespace: "demo", Name: "cfg",
		Principal: normalize.Principal{Human: "alice"},
	}
	out, err := tk.Take(context.Background(), "0123456789abcdef0123456789abcdef", a, engine.Impact{Class: engine.ClassReversible, Measured: true})
	if err != nil || out == "" {
		t.Fatalf("take = %q, %v", out, err)
	}
	got, err := os.ReadFile(filepath.Join(out, "before.json"))
	if err != nil {
		t.Fatalf("before.json: %v", err)
	}
	if string(got) != cm {
		t.Errorf("before.json = %s, want %s", got, cm)
	}
	if st, err := os.Stat(filepath.Join(out, "before.json")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("before.json mode = %v, %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(out, "RESTORE.txt")); err != nil {
		t.Errorf("RESTORE.txt missing: %v", err)
	}
	if got := lastRequest().Header.Get("Impersonate-User"); got != "alice" {
		t.Errorf("Impersonate-User = %q, want alice", got)
	}
}

func TestUpdateOfMissingObjectTakesNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"kind":"Status","code":404}`)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	e := engine.New(&upstream.Upstream{URL: u, Normal: http.DefaultTransport}, time.Second)
	tk := &Taker{Dir: t.TempDir(), Engine: e}
	a := normalize.Action{
		Verb: "update", Version: "v1", Resource: "configmaps", Namespace: "demo", Name: "cfg",
		Principal: normalize.Principal{Human: "alice"},
	}
	out, err := tk.Take(context.Background(), "0123456789abcdef0123456789abcdef", a, engine.Impact{Class: engine.ClassReversible, Measured: true})
	if err != nil || out != "" {
		t.Errorf("take = %q, %v, want nothing taken for an object that does not exist yet", out, err)
	}
}

// An eviction is a create of pods/x/eviction; Engine.Assess scores it as a
// delete of the pod it evicts (mutate.go, the eviction case in Assess), and
// Take must snapshot the same normalisation -- otherwise an approved
// COMPENSABLE/TERMINAL eviction falls through Take's switch as an
// unrecognised verb and gets no undo bundle at all.
func TestEvictionIsSnapshottedAsDelete(t *testing.T) {
	dir := t.TempDir()
	var got model.Action
	tk := &Taker{Dir: dir, SoundingScore: func(_ context.Context, act model.Action, d string) error {
		got = act
		return nil
	}}
	a := normalize.Action{Verb: "create", Resource: "pods", Subresource: "eviction", Version: "v1", Namespace: "demo", Name: "web-1"}
	out, err := tk.Take(context.Background(), "d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7", a, engine.Impact{Class: engine.ClassCompensable, Measured: true})
	if err != nil || out == "" {
		t.Fatalf("take = %q, %v", out, err)
	}
	if got.Verb != "delete" || got.Target.Resource != "pods" || got.Target.Name != "web-1" {
		t.Errorf("sounding got %+v, want a plain delete of the evicted pod", got)
	}
}

// Take must refuse an update/patch snapshot the same way Before itself
// does -- and, just as important, without ever sending the GET Before
// would have sent.
func TestTakeRefusesUpdateWithoutHuman(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"kind":"ConfigMap"}`)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	e := engine.New(&upstream.Upstream{URL: u, Normal: http.DefaultTransport}, time.Second)
	tk := &Taker{Dir: t.TempDir(), Engine: e}
	a := normalize.Action{Verb: "patch", Version: "v1", Resource: "configmaps", Namespace: "demo", Name: "cfg"}
	if _, err := tk.Take(context.Background(), "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4", a, engine.Impact{Class: engine.ClassReversible, Measured: true}); err == nil {
		t.Error("Take for a patch with no human to impersonate succeeded")
	}
	if hit {
		t.Error("Take for a patch with no human to impersonate reached the server")
	}
}

// A sounding failure must not leave the directory it was about to fill
// behind: a later look at snapshots/<id> must find either a complete
// bundle or nothing, never a stub that looks like one.
func TestFailedDeleteSnapshotRemovesPartialDirectory(t *testing.T) {
	dir := t.TempDir()
	requestID := "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"
	tk := &Taker{Dir: dir, SoundingScore: func(context.Context, model.Action, string) error { return os.ErrPermission }}
	a := normalize.Action{Verb: "delete", Version: "v1", Resource: "persistentvolumeclaims", Namespace: "demo", Name: "data"}
	if _, err := tk.Take(context.Background(), requestID, a, engine.Impact{Class: engine.ClassTerminal, Measured: true}); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := os.Stat(filepath.Join(dir, requestID)); !os.IsNotExist(err) {
		t.Errorf("partial snapshot directory still exists (stat err = %v)", err)
	}
}

// Same as above for the update/patch path: a write failure after mkdir
// must not leave a partial before.json/RESTORE.txt behind either.
func TestFailedBeforeWriteRemovesPartialDirectory(t *testing.T) {
	e, _ := apiServer(t, `{"kind":"ConfigMap"}`)
	dir := t.TempDir()
	requestID := "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6"
	// A directory already sitting where before.json needs to go forces
	// os.WriteFile to fail, without depending on filesystem permission
	// behaviour that differs across platforms.
	if err := os.MkdirAll(filepath.Join(dir, requestID, "before.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	tk := &Taker{Dir: dir, Engine: e}
	a := normalize.Action{
		Verb: "patch", Version: "v1", Resource: "configmaps", Namespace: "demo", Name: "cfg",
		Principal: normalize.Principal{Human: "alice"},
	}
	if _, err := tk.Take(context.Background(), requestID, a, engine.Impact{Class: engine.ClassReversible, Measured: true}); err == nil {
		t.Fatal("expected an error writing before.json")
	}
	if _, err := os.Stat(filepath.Join(dir, requestID)); !os.IsNotExist(err) {
		t.Errorf("partial snapshot directory still exists (stat err = %v)", err)
	}
}

func TestRequestIDCannotEscapeTheDir(t *testing.T) {
	tk := &Taker{Dir: t.TempDir(), SoundingScore: func(context.Context, model.Action, string) error {
		t.Fatal("sounding was called with a request id that could escape the directory")
		return nil
	}}
	a := normalize.Action{Verb: "delete", Version: "v1", Resource: "pods", Namespace: "demo", Name: "web"}
	if _, err := tk.Take(context.Background(), "../x", a, engine.Impact{Class: engine.ClassTerminal, Measured: true}); err == nil {
		t.Error("Take with a path-traversal request id succeeded")
	}
}

// Final review I2(b): sounding refuses a cluster-scoped delete other than
// a namespace, which is why it was unmeasured in the first place; asking
// sounding again for the snapshot failed every time, so an approved
// delete of that kind could never be forwarded. The object itself is read
// instead.
func TestUnmeasuredDeleteSnapshotsTheObject(t *testing.T) {
	pv := `{"kind":"PersistentVolume","apiVersion":"v1","metadata":{"name":"pv-1"}}`
	e, lastRequest := apiServer(t, pv)
	tk := &Taker{Dir: t.TempDir(), Engine: e, SoundingScore: func(context.Context, model.Action, string) error {
		t.Error("sounding asked to snapshot a delete it could not measure")
		return os.ErrInvalid
	}}
	a := normalize.Action{Verb: "delete", Version: "v1", Resource: "persistentvolumes", Name: "pv-1",
		Principal: normalize.Principal{Human: "alice"}}
	out, err := tk.Take(context.Background(), "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4", a, engine.Unmeasured("cluster-scoped"))
	if err != nil || out == "" {
		t.Fatalf("take = %q, %v", out, err)
	}
	if got, _ := os.ReadFile(filepath.Join(out, "before.json")); string(got) != pv {
		t.Errorf("before.json = %s", got)
	}
	note, _ := os.ReadFile(filepath.Join(out, "RESTORE.txt"))
	if !strings.Contains(string(note), "kubectl create") {
		t.Errorf("RESTORE.txt does not say how to recreate a deleted object:\n%s", note)
	}
	if r := lastRequest(); r.Method != http.MethodGet || r.URL.Path != "/api/v1/persistentvolumes/pv-1" || r.Header.Get("Impersonate-User") != "alice" {
		t.Errorf("read %s %s as %q", r.Method, r.URL.Path, r.Header.Get("Impersonate-User"))
	}
}

// Final review I2(c): a deletecollection was forwarded with no snapshot at
// all. It is snapshotted as the LIST the API server would delete: same
// path, same selectors, as the human.
func TestDeleteCollectionSnapshotsTheList(t *testing.T) {
	list := `{"kind":"ConfigMapList","apiVersion":"v1","items":[{"metadata":{"name":"a"}}]}`
	e, lastRequest := apiServer(t, list)
	tk := &Taker{Dir: t.TempDir(), Engine: e}
	a := normalize.Action{Verb: "deletecollection", Version: "v1", Resource: "configmaps", Namespace: "demo",
		Path:      "/api/v1/namespaces/demo/configmaps",
		Query:     map[string][]string{"labelSelector": {"app=web"}, "fieldSelector": {"metadata.name=a"}, "propagationPolicy": {"Foreground"}},
		Principal: normalize.Principal{Human: "alice"}}
	out, err := tk.Take(context.Background(), "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5", a, engine.Unmeasured("verb deletecollection"))
	if err != nil || out == "" {
		t.Fatalf("take = %q, %v", out, err)
	}
	if got, _ := os.ReadFile(filepath.Join(out, "list.json")); string(got) != list {
		t.Errorf("list.json = %s", got)
	}
	note, _ := os.ReadFile(filepath.Join(out, "RESTORE.txt"))
	if !strings.Contains(string(note), "objects, not data") {
		t.Errorf("RESTORE.txt does not say it restores objects, not data:\n%s", note)
	}
	r := lastRequest()
	q := r.URL.Query()
	if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/demo/configmaps" || r.Header.Get("Impersonate-User") != "alice" ||
		q.Get("labelSelector") != "app=web" || q.Get("fieldSelector") != "metadata.name=a" || q.Has("propagationPolicy") || q.Has("dryRun") {
		t.Errorf("listed %s %s?%s as %q", r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Impersonate-User"))
	}
}

// A collection that cannot be listed is not an empty one.
func TestDeleteCollectionListFailureIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	e := engine.New(&upstream.Upstream{URL: u, Normal: http.DefaultTransport}, time.Second)
	dir := t.TempDir()
	tk := &Taker{Dir: dir, Engine: e}
	a := normalize.Action{Verb: "deletecollection", Version: "v1", Resource: "configmaps", Namespace: "demo",
		Principal: normalize.Principal{Human: "alice"}}
	if out, err := tk.Take(context.Background(), "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6", a, engine.Unmeasured("x")); err == nil {
		t.Errorf("a failed list was reported as a snapshot %q", out)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("a failed snapshot left %d entries behind", len(ents))
	}
}

// An eviction sounding could not measure is snapshotted by reading the pod
// it evicts: the path Before checks must be the pod's, not the eviction's.
func TestUnmeasuredEvictionSnapshotsThePod(t *testing.T) {
	pod := `{"kind":"Pod","apiVersion":"v1","metadata":{"name":"web-1","namespace":"demo"}}`
	e, lastRequest := apiServer(t, pod)
	tk := &Taker{Dir: t.TempDir(), Engine: e}
	a := normalize.Action{Verb: "create", Version: "v1", Resource: "pods", Subresource: "eviction", Namespace: "demo", Name: "web-1",
		Path: "/api/v1/namespaces/demo/pods/web-1/eviction", Principal: normalize.Principal{Human: "alice"}}
	out, err := tk.Take(context.Background(), "a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7", a, engine.Unmeasured("budget"))
	if err != nil || out == "" {
		t.Fatalf("take = %q, %v", out, err)
	}
	if r := lastRequest(); r.URL.Path != "/api/v1/namespaces/demo/pods/web-1" {
		t.Errorf("read %s", r.URL.Path)
	}
}

// Discard removes only a directory Take made.
func TestDiscardRemovesOnlyItsOwnSnapshot(t *testing.T) {
	root := t.TempDir()
	tk := &Taker{Dir: filepath.Join(root, "snapshots")}
	own, err := tk.write("b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8", "before.json", []byte("{}"), restoreNote)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "keep")
	os.MkdirAll(other, 0o700)
	tk.Discard(other)
	tk.Discard(filepath.Join(tk.Dir, ".."))
	tk.Discard(own)
	if _, err := os.Stat(own); !os.IsNotExist(err) {
		t.Errorf("own snapshot not removed: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("a directory Take did not make was removed: %v", err)
	}
}
