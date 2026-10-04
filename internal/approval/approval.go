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
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/SaiPisey2/blastgate/internal/engine"
	"github.com/SaiPisey2/blastgate/internal/store"
)

// Store is the slice of *store.Store the lifecycle needs.
type Store interface {
	CreateApproval(ctx context.Context, a store.Approval) error
	ApprovalByID(ctx context.Context, id string) (store.Approval, error)
	LatestApproval(ctx context.Context, session, requestDigest string) (store.Approval, error)
	DecideApproval(ctx context.Context, id, status, by, nonce, token string, decided, expires time.Time) error
	ApproveSecond(ctx context.Context, id, firstApproverID, byID, by, nonce, token string, decided, expires time.Time) error
	MarkPartiallyApproved(ctx context.Context, id, approverID, approverName string, at time.Time) error
	ReplaceFirstApprover(ctx context.Context, id, revokedID, approverID, approverName string, at time.Time) error
	ApproverLive(ctx context.Context, id string) (bool, error)
	ConsumeApproval(ctx context.Context, id, nonce string, at time.Time) error
	SetApprovalStatus(ctx context.Context, id, from, to string) error
}

type Service struct {
	Store      Store
	Key        []byte
	TokenTTL   time.Duration
	PendingTTL time.Duration
	// Reauth is how recently an approver must have signed in to approve
	// an access grant; 0 means defaultReauth. A browser session left open
	// all day must not be enough to hand out cluster power.
	Reauth time.Duration
	Now    func() time.Time
}

const defaultReauth = 15 * time.Minute

// Approver is who is approving, as the server knows them -- never as the
// request claims. ID is the approver account (empty from the CLI, which
// has no accounts), Humans the humans linked to it, SignedIn the browser
// session's creation time, Channel "ui" or "cli".
type Approver struct {
	ID, Name string
	Humans   []string
	SignedIn time.Time
	Channel  string // "ui" | "cli"
}

// The refusals the approval rules give. Their texts are shown to the
// approver as they are, by the admin API and the CLI.
var (
	ErrSelfApproval        = errors.New("you can't approve a request made on your behalf")
	ErrNeedsSecondApprover = errors.New("you already approved this; it needs a second person")
	ErrReauthRequired      = errors.New("sign in again to approve access grants")
	ErrChannelNotAllowed   = errors.New("access grants need two approvers in the browser")
)

// NeedsTwo reports whether an approval needs two people: its stored
// impact class is AUTHORITY. It fails closed -- an impact it cannot read,
// an empty class, or a class it does not know all need two -- because
// guessing "one" for an access grant whose impact row was damaged or
// written by a newer version would let a single person grant power.
//
// impact_json is not signed, so the class is trusted only when the
// impact digests to the row's impact_digest, the value the token binds:
// a database writer who rewrites an access grant's class to REVERSIBLE
// without also changing the digest gets two approvers, and one who
// changes the digest too gets a token no retry will ever match. A row
// already partially approved needs two whatever it now says, so an edit
// after the first approval cannot turn the second into a lone release.
func NeedsTwo(a store.Approval) bool {
	if a.Status == "partially_approved" {
		return true
	}
	var imp engine.Impact
	if err := json.Unmarshal(a.ImpactJSON, &imp); err != nil {
		return true
	}
	if imp.Digest() != a.ImpactDigest {
		return true
	}
	switch imp.Class {
	case engine.ClassRead, engine.ClassReversible, engine.ClassCompensable, engine.ClassTerminal:
		return false
	}
	return true
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

// ReauthWindow is the reauth window Approve applies: Reauth, or the
// default when it is unset. serve logs it, so an operator can see the
// window in force rather than the one they meant to set.
func (s *Service) ReauthWindow() time.Duration {
	if s.Reauth == 0 {
		return defaultReauth
	}
	return s.Reauth
}

// Approve applies the approval rules and, when they are met, mints a
// single-use token. Nobody approves a request made on their own behalf.
// An access grant (NeedsTwo) needs two different approver accounts, both
// in the browser and both recently signed in: the first approval only
// records who it was (partially_approved, no token), and only the second
// mints. A first approval counts only while its approver is live: when
// the first approver has been revoked, the arriving approval replaces it
// as the first and releases nothing (ruling E-R15a). The store's
// compare-and-swaps pin the state checked here -- pending for a lone
// approval, the same live first approver for a second -- so two
// approvers, an approve racing a deny, or a revocation landing between
// the read and the write cannot turn into a release the rules refused.
func (s *Service) Approve(ctx context.Context, id string, by Approver) (store.Approval, error) {
	if len(s.Key) == 0 {
		return store.Approval{}, errNoKey
	}
	// decidable first: a lapsed approval is refused before any rule can
	// record a first approver on it (ruling E-R2).
	a, err := s.decidable(ctx, id)
	if err != nil {
		return store.Approval{}, err
	}
	if by.Name == a.Human || slices.Contains(by.Humans, a.Human) {
		return store.Approval{}, ErrSelfApproval
	}
	now := s.Now()
	if NeedsTwo(a) {
		// The CLI has no accounts: its --by is a claim, so it could
		// supply both "people" by typing two names. An approver with no
		// account id is no better: it cannot be told apart from anyone,
		// so it is neither the first person nor the second.
		if by.Channel != "ui" || by.ID == "" {
			return store.Approval{}, ErrChannelNotAllowed
		}
		reauth := s.ReauthWindow()
		// A sign-in time in the future is a clock or data fault, not a
		// fresh sign-in; it must not open the window indefinitely.
		if by.SignedIn.After(now) || now.Sub(by.SignedIn) > reauth {
			return store.Approval{}, ErrReauthRequired
		}
		if a.Status == "pending" {
			if err := s.Store.MarkPartiallyApproved(ctx, id, by.ID, by.Name, now); err != nil {
				return store.Approval{}, err
			}
			return s.Store.ApprovalByID(ctx, id)
		}
		live, err := s.Store.ApproverLive(ctx, a.FirstApproverID)
		if err != nil {
			return store.Approval{}, err
		}
		if !live {
			// The first approver was revoked (perhaps a stolen account):
			// their approval no longer counts, and this one becomes the
			// first of two instead of completing a pair with it.
			if err := s.Store.ReplaceFirstApprover(ctx, id, a.FirstApproverID, by.ID, by.Name, now); err != nil {
				return store.Approval{}, err
			}
			return s.Store.ApprovalByID(ctx, id)
		}
		// The name is compared as well as the id: revoking an approver
		// and creating it again under the same name gives the same person
		// a new id, and the id alone would let them approve twice. Names
		// are compared without case, so Bob and bob are one person here
		// (self-approval stays exact, as names are recorded).
		if by.ID == a.FirstApproverID || strings.EqualFold(by.Name, a.FirstApproverName) {
			return store.Approval{}, ErrNeedsSecondApprover
		}
		nonce := NewID()
		expires := now.Add(s.TokenTTL)
		token := s.Token(a, nonce, expires)
		if err := s.Store.ApproveSecond(ctx, id, a.FirstApproverID, by.ID, by.Name, nonce, token, now, expires); err != nil {
			return store.Approval{}, err
		}
		return s.Store.ApprovalByID(ctx, id)
	}
	nonce := NewID()
	expires := now.Add(s.TokenTTL)
	token := s.Token(a, nonce, expires)
	if err := s.Store.DecideApproval(ctx, id, "approved", by.Name, nonce, token, now, expires); err != nil {
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

// decidable loads an approval a human may still decide: pending (or
// partially approved, waiting on a second person) and not past its
// expiry. A stale one must not be approved — the impact the human is
// looking at may be an hour old.
func (s *Service) decidable(ctx context.Context, id string) (store.Approval, error) {
	a, err := s.Store.ApprovalByID(ctx, id)
	if err != nil {
		return store.Approval{}, err
	}
	if a.Status != "pending" && a.Status != "partially_approved" {
		return store.Approval{}, notPending(fmt.Sprintf("approval %s is %s, not pending", id, a.Status))
	}
	if s.Now().After(a.Expires) {
		return store.Approval{}, notPending(fmt.Sprintf("approval %s is %s but expired", id, a.Status))
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
	// A partial approval is still waiting on its second person: the same
	// answer as pending, expiring on the same deadline, never releasable.
	case "pending", "partially_approved":
		if now.After(a.Expires) {
			return s.expire(ctx, a, a.Status)
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
