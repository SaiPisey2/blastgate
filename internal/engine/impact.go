// Package engine measures what an action would do (design §3.3). It never
// writes: deletes are scored by sounding's read-only engine, and every
// other mutation by the API server's own dry-run, sent impersonated as the
// session's human so it sees exactly their rights and admission.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	ClassRead        = "READ"
	ClassReversible  = "REVERSIBLE"
	ClassCompensable = "COMPENSABLE"
	ClassTerminal    = "TERMINAL"
	ClassAuthority   = "AUTHORITY"
)

type Effect struct {
	Kind        string `json:"kind"`
	Object      string `json:"object"` // Kind/namespace/name
	Explanation string `json:"explanation,omitempty"`
}

type Impact struct {
	Class          string         `json:"class"`
	Measured       bool           `json:"measured"`
	Reason         string         `json:"reason,omitempty"`
	Effects        []Effect       `json:"effects,omitempty"`
	DataDestroyed  int            `json:"dataDestroyed"`
	EndpointsLeft  map[string]int `json:"endpointsLeft,omitempty"`
	PDBViolations  []string       `json:"pdbViolations,omitempty"`
	SQLDetected    bool           `json:"sqlDetected"`
	DryRunRejected bool           `json:"dryRunRejected"`
	Undo           string         `json:"undo"`
	Elapsed        time.Duration  `json:"-"`
}

// Unmeasured is the impact of anything this build could not measure. It is
// TERMINAL -- the worst class -- so a policy, a replay or a person reading
// the audit never mistakes "we did not look" for "nothing happens".
func Unmeasured(reason string) Impact {
	return Impact{Class: ClassTerminal, Measured: false, Reason: reason, Undo: "none"}
}

// Digest identifies the measured impact. An approval is bound to it, and a
// retry is released only when a fresh measurement digests the same: the
// person approved these consequences, not whatever the cluster has become.
// Order-only differences and timing must not change it.
func (i Impact) Digest() string {
	c := i
	c.Elapsed = 0
	c.PDBViolations = append([]string(nil), i.PDBViolations...)
	sort.Strings(c.PDBViolations)
	c.Effects = append([]Effect(nil), i.Effects...)
	sort.Slice(c.Effects, func(a, b int) bool {
		if c.Effects[a].Object != c.Effects[b].Object {
			return c.Effects[a].Object < c.Effects[b].Object
		}
		return c.Effects[a].Kind < c.Effects[b].Kind
	})
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Summary is the one-line description sent to the client in a ticket. It
// carries class and counts only: object names come from the cluster, which
// the agent can write to, and client messages carry no data blastgate did
// not generate itself.
func (i Impact) Summary() string {
	emptied := 0
	for _, n := range i.EndpointsLeft {
		if n == 0 {
			emptied++
		}
	}
	parts := []string{i.Class, plural(len(i.Effects), "object")}
	if i.DataDestroyed > 0 {
		parts = append(parts, plural(i.DataDestroyed, "volume")+" with data destroyed")
	}
	if emptied > 0 {
		parts = append(parts, plural(emptied, "service")+" left with no backends")
	}
	if len(i.PDBViolations) > 0 {
		parts = append(parts, plural(len(i.PDBViolations), "disruption budget")+" broken")
	}
	if !i.Measured {
		parts = append(parts, "not measured")
	}
	return strings.Join(parts, ", ")
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}
