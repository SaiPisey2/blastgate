// Package approval turns a human's decision on a held request into a
// token that releases exactly that request, with exactly the impact the
// human saw, exactly once. The token is an HMAC the database cannot forge:
// a row edited to match a new measurement still fails verification,
// because verification recomputes over the fresh measurement, not the row.
package approval

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/SaiPisey2/blastgate/internal/store"
)

// Store is the slice of *store.Store the lifecycle needs.
type Store interface {
	CreateApproval(ctx context.Context, a store.Approval) error
	ApprovalByID(ctx context.Context, id string) (store.Approval, error)
	LatestApproval(ctx context.Context, session, requestDigest string) (store.Approval, error)
	DecideApproval(ctx context.Context, id, status, by, nonce, token string, decided, expires time.Time) error
	ConsumeApproval(ctx context.Context, id, nonce string, at time.Time) error
	SetApprovalStatus(ctx context.Context, id, from, to string) error
}

type Service struct {
	Store      Store
	Key        []byte
	TokenTTL   time.Duration
	PendingTTL time.Duration
	Now        func() time.Time
}

// Outcome is what a retried request should do with its latest approval.
type Outcome int

const (
	Release Outcome = iota // forward it: the approval was valid and is now spent
	Pending                // wait on the existing pending approval
	Denied                 // refuse: a human said no and the denial still stands
	Void                   // the approval no longer matches; it is superseded
	None                   // nothing usable: the caller creates a new pending approval
	// Verified is Verify's answer for a valid approval it has NOT spent:
	// the caller snapshots, then calls Consume, and forwards only if that
	// succeeds. Last, so the values above keep their numbers.
	Verified
)

func (o Outcome) String() string {
	switch o {
	case Release:
		return "release"
	case Pending:
		return "pending"
	case Denied:
		return "denied"
	case Void:
		return "void"
	case None:
		return "none"
	case Verified:
		return "verified"
	}
	return "outcome(" + strconv.Itoa(int(o)) + ")"
}

// errNoKey is returned instead of minting or honouring a token without a
// key: an HMAC under an empty key is computable by anyone who can read
// the row, which would make every approval forgeable.
var errNoKey = errors.New("approval signing key is empty")

// NewID returns 16 random bytes as hex. crypto/rand, because approval IDs
// and nonces are shown to agents and must not be guessable.
func NewID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Token is the HMAC-SHA256, hex, over
// approval_id|session|human|agent|request_digest|impact_digest|nonce|expiry_ms.
// Every field is bound so the token cannot be carried to another
// approval, session, human, agent, request, a different measured impact,
// or past its expiry. The join stays unambiguous because at most one
// field can contain '|': the human (any printable ASCII). The ID and
// session are hex, read from the left; agent (a DNS label), digests,
// nonce and expiry contain no '|' either, read from the right; whatever
// is left is the human. A second free-text field would break that.
//
// With no key it returns "": an HMAC under an empty key is computable by
// anyone who can read the row, and "" never equals a minted token.
func (s *Service) Token(a store.Approval, nonce string, expires time.Time) string {
	if len(s.Key) == 0 {
		return ""
	}
	msg := strings.Join([]string{a.ID, a.Session, a.Human, a.Agent, a.RequestDigest, a.ImpactDigest, nonce, strconv.FormatInt(expires.UnixMilli(), 10)}, "|")
	m := hmac.New(sha256.New, s.Key)
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

// Approve mints a single-use token for a pending approval. The store's
// compare-and-swap on status='pending' is what stops two approvers (or an
// approve racing a deny) from both succeeding; the checks here only give
// a clear error for the common cases.
func (s *Service) Approve(ctx context.Context, id, by string) (store.Approval, error) {
	if len(s.Key) == 0 {
		return store.Approval{}, errNoKey
	}
	a, err := s.decidable(ctx, id)
	if err != nil {
		return store.Approval{}, err
	}
	now := s.Now()
	nonce := NewID()
	expires := now.Add(s.TokenTTL)
	token := s.Token(a, nonce, expires)
	if err := s.Store.DecideApproval(ctx, id, "approved", by, nonce, token, now, expires); err != nil {
		return store.Approval{}, err
	}
	return s.Store.ApprovalByID(ctx, id)
}

// Deny records a refusal that blocks retries of the same request for the
// pending lifetime, so an agent cannot simply retry past a "no".
func (s *Service) Deny(ctx context.Context, id, by string) (store.Approval, error) {
	if _, err := s.decidable(ctx, id); err != nil {
		return store.Approval{}, err
	}
	now := s.Now()
	if err := s.Store.DecideApproval(ctx, id, "denied", by, "", "", now, now.Add(s.PendingTTL)); err != nil {
		return store.Approval{}, err
	}
	return s.Store.ApprovalByID(ctx, id)
}

// ErrNotPending is what Approve and Deny return, via errors.Is, for an
// approval a human can no longer decide: already decided, spent, or
// pending past its expiry. The admin API answers it with 409 rather than
// 500; without a sentinel it could only tell "wrong state" from "blastgate
// failed" by matching message text.
var ErrNotPending = errors.New("approval is not pending")

// notPendingError keeps the CLI's long-standing message text while
// matching ErrNotPending.
type notPendingError string

func notPending(msg string) error              { return notPendingError(msg) }
func (e notPendingError) Error() string        { return string(e) }
func (e notPendingError) Is(target error) bool { return target == ErrNotPending }

// decidable loads an approval a human may still decide: pending and not
// past its expiry. A stale pending one must not be approved — the impact
// the human is looking at may be an hour old.
func (s *Service) decidable(ctx context.Context, id string) (store.Approval, error) {
	a, err := s.Store.ApprovalByID(ctx, id)
	if err != nil {
		return store.Approval{}, err
	}
	if a.Status != "pending" {
		return store.Approval{}, notPending(fmt.Sprintf("approval %s is %s, not pending", id, a.Status))
	}
	if s.Now().After(a.Expires) {
		return store.Approval{}, notPending(fmt.Sprintf("approval %s is pending but expired", id))
	}
	return a, nil
}

// Check is Verify and Consume in one step: Release when this call spent
// the approval, None when a concurrent retry spent it first.
func (s *Service) Check(ctx context.Context, session, human, agent, requestDigest, impactDigest string) (Outcome, store.Approval, error) {
	o, a, err := s.Verify(ctx, session, human, agent, requestDigest, impactDigest)
	if err != nil || o != Verified {
		return o, a, err
	}
	if err := s.Consume(ctx, a); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return None, a, nil
		}
		return None, a, err
	}
	a.Status = "consumed"
	return Release, a, nil
}

// Consume spends an approval Verify returned as Verified. The store's
// consume is the single-use gate: status and nonce move in one
// transaction, so of two retries that both verified, exactly one gets
// nil and the other ErrConflict. A token that lapsed since Verify -- a
// slow snapshot in between -- is ErrConflict too, never spent late.
func (s *Service) Consume(ctx context.Context, a store.Approval) error {
	now := s.Now()
	if now.After(a.Expires) {
		if _, _, err := s.expire(ctx, a, "approved"); err != nil {
			return err
		}
		return store.ErrConflict
	}
	return s.Store.ConsumeApproval(ctx, a.ID, a.Nonce, now)
}

// Verify is the retry path. session, human and agent come from the
// retrying request's authenticated session, never from the approval row;
// requestDigest and impactDigest are freshly computed for this retry. Any
// error means the caller must hold, never forward. It never spends an
// approval: Verified means "valid now", and the caller must Consume it
// before forwarding -- after the snapshot, so a failed snapshot leaves
// the human's approval for the next retry instead of burning it.
func (s *Service) Verify(ctx context.Context, session, human, agent, requestDigest, impactDigest string) (Outcome, store.Approval, error) {
	if len(s.Key) == 0 {
		return None, store.Approval{}, errNoKey
	}
	a, err := s.Store.LatestApproval(ctx, session, requestDigest)
	if errors.Is(err, store.ErrNotFound) {
		return None, store.Approval{}, nil
	}
	if err != nil {
		return None, store.Approval{}, err
	}
	now := s.Now()
	switch a.Status {
	case "pending":
		if now.After(a.Expires) {
			return s.expire(ctx, a, "pending")
		}
		return Pending, a, nil
	case "denied":
		if now.After(a.Expires) {
			return None, a, nil
		}
		return Denied, a, nil
	case "approved":
		if now.After(a.Expires) {
			return s.expire(ctx, a, "approved")
		}
		// Recompute over what this retry actually is — this session,
		// human and agent, this request, this fresh impact — not over the
		// row's own fields. A changed impact, a different caller, or a row
		// edited to match (moved to another session, expiry extended,
		// nonce swapped) all fail here, because the stored token was
		// computed over the approved values under a key the database
		// does not hold.
		fresh := a
		fresh.Session = session
		fresh.Human = human
		fresh.Agent = agent
		fresh.RequestDigest = requestDigest
		fresh.ImpactDigest = impactDigest
		want := s.Token(fresh, a.Nonce, a.Expires)
		if !hmac.Equal([]byte(want), []byte(a.Token)) {
			// ErrConflict means the row already left 'approved' (spent or
			// superseded by a concurrent retry); either way it is not
			// releasable, so the answer is still Void.
			if err := s.Store.SetApprovalStatus(ctx, a.ID, "approved", "superseded"); err != nil && !errors.Is(err, store.ErrConflict) {
				return None, a, err
			}
			a.Status = "superseded"
			return Void, a, nil
		}
		return Verified, a, nil
	default: // consumed, superseded, expired: terminal, never reusable
		return None, a, nil
	}
}

// expire marks a lapsed approval expired. Losing the race (ErrConflict)
// is fine: whatever moved it, it is no longer usable, so None stands.
func (s *Service) expire(ctx context.Context, a store.Approval, from string) (Outcome, store.Approval, error) {
	if err := s.Store.SetApprovalStatus(ctx, a.ID, from, "expired"); err != nil && !errors.Is(err, store.ErrConflict) {
		return None, a, err
	}
	a.Status = "expired"
	return None, a, nil
}
