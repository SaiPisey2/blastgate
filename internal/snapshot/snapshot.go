// Package snapshot captures what a risky write would change before
// blastgate forwards it, so a person who later wants it back has something
// to restore from -- design's undo story for the writes sounding cannot
// simply reverse. A delete delegates to sounding's own snapshot (it knows
// the cascade a delete takes with it); an update or patch, which changes an
// object rather than removing it, gets its own "before" read written
// straight to disk.
package snapshot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

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

	switch {
	case a.Verb == "delete":
		if i.Class != engine.ClassCompensable && i.Class != engine.ClassTerminal {
			// A reversible delete (a Pod its controller recreates, for
			// example) needs no undo bundle beyond what the controller
			// already provides.
			return "", nil
		}
		return t.takeDelete(ctx, requestID, a)
	case a.Verb == "update" || a.Verb == "patch":
		return t.takeBefore(ctx, requestID, a)
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
		// The caller refuses to forward on this error regardless, so the
		// half-written directory is never mistaken for a usable snapshot.
		return "", fmt.Errorf("snapshot: sounding: %w", err)
	}
	return dir, nil
}

func (t *Taker) takeBefore(ctx context.Context, requestID string, a normalize.Action) (string, error) {
	if t.Engine == nil {
		return "", errors.New("snapshot: no engine to read the live object with")
	}
	before, err := t.Engine.Before(ctx, a)
	if err != nil {
		return "", fmt.Errorf("snapshot: reading the live object: %w", err)
	}
	if before == nil {
		// Nothing lives at this name yet: an update or patch that
		// upserts has no "before" to restore.
		return "", nil
	}
	dir, err := t.mkdir(requestID)
	if err != nil {
		return "", err
	}
	// 0600: the live object's full spec (Secrets included) must not be
	// world- or group-readable on disk.
	if err := os.WriteFile(filepath.Join(dir, "before.json"), before, 0o600); err != nil {
		return "", fmt.Errorf("snapshot: writing before.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "RESTORE.txt"), []byte(restoreNote), 0o600); err != nil {
		return "", fmt.Errorf("snapshot: writing RESTORE.txt: %w", err)
	}
	return dir, nil
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
