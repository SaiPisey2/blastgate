package engine_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SaiPisey2/blastgate/internal/approval"
	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/store"
)

// NeedsTwo trusts a stored class only when the stored impact digests to
// the stored impact_digest. Any engine impact whose digest changed across
// the gate's json.Marshal and the store would silently make every held
// request of that class need two people (or, for AUTHORITY, keep needing
// them -- the safe direction). So every class the engine really produces
// goes through the store the way the gate writes it, and comes back with
// the answer its class deserves: one approver for READ, REVERSIBLE,
// COMPENSABLE and TERMINAL, two for AUTHORITY.
func TestRealImpactsRoundTripThroughTheStore(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "bg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	classes := map[string]bool{}
	n := 0
	for name, imp := range engine.RealImpacts(t) {
		n++
		classes[imp.Class] = true
		b, err := json.Marshal(imp)
		if err != nil {
			t.Fatal(err)
		}
		a := store.Approval{ID: approval.NewID(), Session: "s1", Human: "alice", Agent: "coding-agent", RequestDigest: name,
			ImpactDigest: imp.Digest(), ActionJSON: []byte(`{}`), ImpactJSON: b, Rule: "r", Status: "pending", Created: now, Expires: now.Add(time.Hour)}
		if err := st.CreateApproval(ctx, a); err != nil {
			t.Fatal(err)
		}
		got, err := st.ApprovalByID(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		var back engine.Impact
		if err := json.Unmarshal(got.ImpactJSON, &back); err != nil || back.Digest() != got.ImpactDigest {
			t.Errorf("%s: stored impact does not digest to its stored digest (%v)", name, err)
		}
		want := strings.HasPrefix(name, "authority")
		if (imp.Class == engine.ClassAuthority) != want {
			t.Fatalf("%s: class %s", name, imp.Class)
		}
		if got := approval.NeedsTwo(got); got != want {
			t.Errorf("%s (class %s, measured %v): NeedsTwo = %v, want %v", name, imp.Class, imp.Measured, got, want)
		}
	}
	for _, c := range []string{engine.ClassRead, engine.ClassReversible, engine.ClassCompensable, engine.ClassTerminal, engine.ClassAuthority} {
		if !classes[c] {
			t.Errorf("no real impact of class %s was round-tripped", c)
		}
	}
	if n < 10 {
		t.Errorf("only %d impacts", n)
	}
}
