// Package snapshot captures what a risky write would change before
// blastgate forwards it, so a person who later wants it back has something
// to restore from -- design's undo story for the writes sounding cannot
// simply reverse. A measured delete delegates to sounding's own snapshot
// (it knows the cascade a delete takes with it); an update or patch, and a
// delete sounding could not measure, gets its own "before" read written
// straight to disk; a deletecollection gets the LIST it would empty.
package snapshot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/SaiPisey2/sounding/pkg/model"

	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/normalize"
)

// requestIDPattern is the gate's own request ID shape (16 random bytes,
// hex): a snapshot directory named from anything else -- in particular a
// "." or ".." segment -- could land outside Dir. Take refuses instead of
// trusting a caller to have generated the ID itself.
var requestIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// restoreNote explains what before.json can and cannot put back. Written
// once per snapshot, next to the file it describes, since the file alone
// does not say that kubectl replace only restores the spec, not data a
// controller wrote afterward.
const restoreNote = `This directory holds the object as it was immediately before a write
blastgate forwarded.

    kubectl replace -f before.json

restores its metadata and spec to that state. It does not restore data a
controller or another process wrote into the object afterward, and it does
not restore anything the resourceVersion in before.json no longer matches
in the live cluster.
`

// deletedNote is restoreNote for an object deleted outright, snapshotted
// by reading it because sounding could not score the delete (a
// cluster-scoped object other than a namespace, or any delete it refused).
// replace needs a live object; a deleted one is created again, and create
// refuses a resourceVersion or uid.
const deletedNote = `This directory holds the object as it was immediately before blastgate
forwarded a delete of it. blastgate could not measure that delete, so this
is the object alone: not anything the delete took with it.

Remove metadata.resourceVersion, metadata.uid and metadata.creationTimestamp
from before.json, then

    kubectl create -f before.json

recreates the object. This restores objects, not data: whatever a deleted
volume held, or a controller kept elsewhere, is not in this file.
`

// listNote explains list.json, the collection a deletecollection emptied.
const listNote = `This directory holds the collection a deletecollection removed, as the
API server listed it (same path, same labelSelector and fieldSelector)
immediately before blastgate forwarded the delete.

Take each object in list.json's "items", remove metadata.resourceVersion,
metadata.uid and metadata.creationTimestamp, and create it again with
kubectl create -f. This restores objects, not data: whatever a deleted
volume held is gone.
`

// Taker takes an undo snapshot before a risky write is forwarded.
type Taker struct {
	// Dir is the snapshots root; a request's own snapshot lands in
	// Dir/<requestID>.
	Dir string
	// Engine reads the live "before" object for an update or patch,
	// impersonated the same way the dry-run that scored it was.
	Engine *engine.Engine
	// SoundingScore is sounding's score.Score, scoped to a delete and a
	// snapshot directory. A field so tests can supply a fake that never
	// touches a cluster or a disk beyond the directory Take already made.
	SoundingScore func(ctx context.Context, act model.Action, dir string) error
}

// Take captures the "before" state of a's target when the write is about
// to be forwarded, and returns the directory it wrote into -- or "" when
// this action needs no snapshot (a reversible delete, or an update/patch
// of an object that does not exist yet). A failed snapshot is always
// returned as an error, never as "" with no error: the caller (the gate,
// wired in a later task) must be able to tell "nothing to take" from "the
// take failed" and refuse to forward on the latter.
func (t *Taker) Take(ctx context.Context, requestID string, a normalize.Action, i engine.Impact) (string, error) {
	if !requestIDPattern.MatchString(requestID) {
		// A caller passing anything else -- in particular a "." or ".."
		// segment -- must not get as far as a path built from it.
		return "", fmt.Errorf("snapshot: %q is not a valid request id", requestID)
	}

	if a.Resource == "pods" && a.Subresource == "eviction" && a.Verb == "create" {
		// Engine.Assess scores an eviction as a delete of the pod it
		// evicts; Take must snapshot the same normalisation, or an
		// approved COMPENSABLE/TERMINAL eviction would fall through this
		// switch below with no undo bundle at all.
		a.Verb, a.Subresource = "delete", ""
		// The path too: Before cross-checks it against the parsed parts,
		// and an unmeasured eviction is snapshotted by reading the pod.
		a.Path = strings.TrimSuffix(strings.TrimRight(a.Path, "/"), "/eviction")
	}

	switch {
	case a.Verb == "delete":
		if i.Class != engine.ClassCompensable && i.Class != engine.ClassTerminal {
			// A reversible delete (a Pod its controller recreates, for
			// example) needs no undo bundle beyond what the controller
			// already provides.
			return "", nil
		}
		if !i.Measured {
			// sounding already refused or failed to score this delete --
			// a cluster-scoped object other than a namespace, for one.
			// Asking it again for the snapshot fails the same way, and an
			// approved delete would then never be forwardable.
			return t.takeBefore(ctx, requestID, a, deletedNote)
		}
		return t.takeDelete(ctx, requestID, a)
	case a.Verb == "deletecollection":
		return t.takeList(ctx, requestID, a)
	case a.Verb == "update" || a.Verb == "patch":
		return t.takeBefore(ctx, requestID, a, restoreNote)
	default:
		return "", nil
	}
}

func (t *Taker) takeDelete(ctx context.Context, requestID string, a normalize.Action) (string, error) {
	if t.SoundingScore == nil {
		return "", errors.New("snapshot: no sounding scorer configured")
	}
	dir, err := t.mkdir(requestID)
	if err != nil {
		return "", err
	}
	act := model.Action{Verb: "delete", Target: model.Target{
		Group: a.Group, Version: a.Version, Resource: a.Resource, Namespace: a.Namespace, Name: a.Name,
	}}
	if err := t.SoundingScore(ctx, act, dir); err != nil {
		// sounding writes its bundle incrementally; a failure partway
		// through can leave one behind that looks complete but is not.
		// The caller refuses to forward on this error regardless, but the
		// directory itself must not survive to be found later and mistaken
		// for a usable snapshot.
		cleanup(dir)
		return "", fmt.Errorf("snapshot: sounding: %w", err)
	}
	return dir, nil
}

func (t *Taker) takeBefore(ctx context.Context, requestID string, a normalize.Action, note string) (string, error) {
	if t.Engine == nil {
		return "", errors.New("snapshot: no engine to read the live object with")
	}
	before, err := t.Engine.Before(ctx, a)
	if err != nil {
		return "", fmt.Errorf("snapshot: reading the live object: %w", err)
	}
	if before == nil {
		// Nothing lives at this name yet: an update or patch that
		// upserts has no "before" to restore, and a delete of it will be
		// refused as not found.
		return "", nil
	}
	return t.write(requestID, "before.json", before, note)
}

func (t *Taker) takeList(ctx context.Context, requestID string, a normalize.Action) (string, error) {
	if t.Engine == nil {
		return "", errors.New("snapshot: no engine to list the collection with")
	}
	list, err := t.Engine.List(ctx, a)
	if err != nil {
		return "", fmt.Errorf("snapshot: listing the collection: %w", err)
	}
	return t.write(requestID, "list.json", list, listNote)
}

// write makes the request's directory and writes data and its RESTORE.txt
// into it, removing the directory again if either write fails.
func (t *Taker) write(requestID, name string, data []byte, note string) (string, error) {
	dir, err := t.mkdir(requestID)
	if err != nil {
		return "", err
	}
	// 0600: the live object's full spec (Secrets included) must not be
	// world- or group-readable on disk.
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		cleanup(dir)
		return "", fmt.Errorf("snapshot: writing %s: %w", name, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "RESTORE.txt"), []byte(note), 0o600); err != nil {
		cleanup(dir)
		return "", fmt.Errorf("snapshot: writing RESTORE.txt: %w", err)
	}
	return dir, nil
}

// Discard removes a snapshot the gate took but will not forward on -- the
// approval it was taken for was spent by a concurrent retry, or the
// snapshot finished past its time limit. Left behind, it would look like
// the undo bundle of a write that never happened.
func (t *Taker) Discard(path string) {
	if path == "" || filepath.Dir(path) != filepath.Clean(t.Dir) || !requestIDPattern.MatchString(filepath.Base(path)) {
		// Only a directory Take itself made: never a path from elsewhere.
		return
	}
	cleanup(path)
}

// cleanup removes an already-made snapshot directory, best effort, after a
// step past mkdir fails: the caller is already returning the real error,
// and a half-written directory left behind could otherwise be found later
// and mistaken for a complete snapshot.
func cleanup(dir string) {
	_ = os.RemoveAll(dir)
}

// mkdir makes this request's snapshot directory, mode 0700: only blastgate
// (and whoever it hands the path to for a restore) should be able to read
// a bundle that may hold Secret data or a PVC's contents.
func (t *Taker) mkdir(requestID string) (string, error) {
	dir := filepath.Join(t.Dir, requestID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("snapshot: making %s: %w", dir, err)
	}
	return dir, nil
}
