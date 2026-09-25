// Package admin serves the approver-facing UI API. This file is its front
// door: an approver trades the bga_ token `blastgate approver new` printed
// for a browser session, and every other /api route goes through Require.
package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SaiPisey2/blastgate/internal/store"
)

const (
	LoginTokenPrefix = "bga_"
	SessionTTL       = 12 * time.Hour
	SessionCookie    = "blastgate_session"
	CSRFHeader       = "X-Blastgate-CSRF"

	loginBodyLimit = 4 << 10
	loginAttempts  = 5
	loginWindow    = time.Minute
	// limiterHosts bounds the limiter's memory. Past it a new address is
	// refused rather than tracked: a flood from many addresses must not
	// grow the map without end, and a login token is 256 random bits, so
	// turning a real approver away for a minute costs less than letting
	// the map grow.
	limiterHosts = 4096
)

// AuthStore is the slice of *store.Store that authentication needs.
type AuthStore interface {
	ApproverByTokenHash(ctx context.Context, h []byte) (store.Approver, error)
	CreateUISession(ctx context.Context, u store.UISession, idHash []byte) error
	UISessionByHash(ctx context.Context, h []byte) (store.UISession, error)
	RevokeUISession(ctx context.Context, idHash []byte, at time.Time) error
}

type Auth struct {
	Store   AuthStore
	Now     func() time.Time
	Log     *slog.Logger
	limiter *limiter
}

func NewAuth(st AuthStore, log *slog.Logger) *Auth {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Auth{Store: st, Now: time.Now, Log: log, limiter: newLimiter()}
}

// NewLoginToken returns a fresh approver token and the hash to store. The
// token is printed once and never kept; only the hash reaches the DB.
func NewLoginToken() (token string, hash []byte) {
	token = LoginTokenPrefix + randomString()
	return token, hashOf(token)
}

func hashOf(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// randomString is 32 bytes from crypto/rand, base64url. rand.Read never
// returns an error (it panics instead on a broken system source), so
// there is no weaker fallback path to take by mistake.
func randomString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Every refusal a client can cause says the same thing: a caller probing
// tokens learns nothing about which exist or which were revoked.
const (
	errUnauthenticated = `{"error":"unauthenticated"}`
	errCSRF            = `{"error":"missing or wrong csrf header"}`
	errLimited         = `{"error":"too many login attempts"}`
	errInternal        = `{"error":"internal error"}`
)

func writeJSON(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write([]byte(body))
}

// remoteHost is the limiter's key. It is the connection's own address and
// never X-Forwarded-For: a header the client writes would let every
// attempt claim a fresh address.
func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Login is POST /api/login {"token": "bga_..."}. Success sets the session
// cookie and returns {"name","csrf"}; the browser keeps the CSRF value in
// memory and echoes it on every state-changing call.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	host := remoteHost(r)
	// Before reading the body, let alone a lookup: a limited address costs
	// nothing and learns nothing, even when it finally sends a good token.
	if !a.limiter.allow(host, a.Now()) {
		a.Log.Warn("login refused", "remote", host, "reason", "rate limited")
		writeJSON(w, http.StatusTooManyRequests, errLimited)
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, loginBodyLimit)).Decode(&body); err != nil {
		a.refuse(w, host, "unreadable body")
		return
	}
	if !strings.HasPrefix(body.Token, LoginTokenPrefix) {
		a.refuse(w, host, "not a login token")
		return
	}
	ap, err := a.Store.ApproverByTokenHash(r.Context(), hashOf(body.Token))
	if errors.Is(err, store.ErrNotFound) {
		a.refuse(w, host, "unknown token")
		return
	}
	if err != nil {
		a.internal(w, "approver lookup", err)
		return
	}
	if !ap.Revoked.IsZero() {
		a.refuse(w, host, "approver revoked")
		return
	}
	id, csrf := randomString(), randomString()
	now := a.Now()
	u := store.UISession{ApproverID: ap.ID, ApproverName: ap.Name, CSRF: csrf, Created: now, Expires: now.Add(SessionTTL)}
	if err := a.Store.CreateUISession(r.Context(), u, hashOf(id)); err != nil {
		a.internal(w, "create ui session", err)
		return
	}
	http.SetCookie(w, sessionCookie(id, int(SessionTTL/time.Second)))
	out, _ := json.Marshal(map[string]string{"name": ap.Name, "csrf": csrf})
	a.Log.Info("login", "remote", host, "approver", ap.Name)
	writeJSON(w, http.StatusOK, string(out))
}

func (a *Auth) refuse(w http.ResponseWriter, host, reason string) {
	a.Log.Warn("login refused", "remote", host, "reason", reason)
	writeJSON(w, http.StatusUnauthorized, errUnauthenticated)
}

func (a *Auth) internal(w http.ResponseWriter, what string, err error) {
	a.Log.Error("admin auth: "+what, "err", err)
	writeJSON(w, http.StatusInternalServerError, errInternal)
}

// sessionCookie builds the one cookie shape used both to set and to
// clear: a clearing cookie whose attributes differed (say, without
// Secure) could be refused or land as a second cookie beside the first.
// Secure and SameSite=Strict are what keep another origin from riding
// the session; HttpOnly keeps page script from reading it.
func sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

// clearCookie makes the browser drop the cookie (Max-Age=0 on the wire).
func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, sessionCookie("", -1))
}

// Logout revokes the session the cookie names and clears the cookie. It
// answers 204 whatever the cookie held: logging out of a session that is
// already gone is not an error worth showing.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
		err := a.Store.RevokeUISession(r.Context(), hashOf(c.Value), a.Now())
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			a.internal(w, "revoke ui session", err)
			return
		}
	}
	clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// Require passes a request on only with a live session: known, unexpired,
// not logged out, and its approver not revoked. A presented cookie that
// fails is cleared so the browser stops sending it. Every method but GET
// must also carry the session's CSRF value in X-Blastgate-CSRF; the
// session check comes first so a logged-out UI sees 401 (log in again),
// not 403.
func (a *Auth) Require(next func(http.ResponseWriter, *http.Request, store.UISession)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(SessionCookie)
		if err != nil || c.Value == "" {
			writeJSON(w, http.StatusUnauthorized, errUnauthenticated)
			return
		}
		u, err := a.Store.UISessionByHash(r.Context(), hashOf(c.Value))
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			a.internal(w, "ui session lookup", err)
			return
		}
		// Both revocations count: RevokeApprover sweeps the approver's
		// sessions, but a login racing that sweep can insert a session it
		// never saw, so the approver's own state is checked here too.
		if err != nil || !u.Revoked.IsZero() || !u.ApproverRevoked.IsZero() || !a.Now().Before(u.Expires) {
			clearCookie(w)
			writeJSON(w, http.StatusUnauthorized, errUnauthenticated)
			return
		}
		if r.Method != http.MethodGet {
			got := r.Header.Get(CSRFHeader)
			// Constant time, so the comparison's duration does not leak how
			// much of a guess was right. The empty check stops two empty
			// strings (which compare equal) from ever counting as a match.
			if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(u.CSRF)) != 1 {
				writeJSON(w, http.StatusForbidden, errCSRF)
				return
			}
		}
		next(w, r, u)
	})
}

// limiter is a fixed window per host: at most loginAttempts in each
// loginWindow, counted from the host's first attempt in that window.
// Every attempt counts, a success included, so an address cannot reset
// its budget by logging in with a token it already has.
type limiter struct {
	mu    sync.Mutex
	hosts map[string]*window
}

type window struct {
	start time.Time
	n     int
}

func newLimiter() *limiter { return &limiter{hosts: map[string]*window{}} }

func (l *limiter) allow(host string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Pruned on every call, so hosts that stopped trying do not pile up.
	for h, w := range l.hosts {
		if !now.Before(w.start.Add(loginWindow)) {
			delete(l.hosts, h)
		}
	}
	w, ok := l.hosts[host]
	if !ok {
		if len(l.hosts) >= limiterHosts {
			return false
		}
		w = &window{start: now}
		l.hosts[host] = w
	}
	if w.n >= loginAttempts {
		return false
	}
	w.n++
	return true
}

func (l *limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.hosts)
}
