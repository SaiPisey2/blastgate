package snapshot

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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

// apiServer answers every GET with cm's body, regardless of path -- Before's
// own path building is exercised in the engine package; here only that
// Take writes what Before returns.
func apiServer(t *testing.T, body string) *engine.Engine {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return engine.New(&upstream.Upstream{URL: u, Normal: http.DefaultTransport}, time.Second)
}

func TestPatchWritesBeforeObject(t *testing.T) {
	cm := `{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"cfg","namespace":"demo"},"data":{"k":"v"}}`
	e := apiServer(t, cm)
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
