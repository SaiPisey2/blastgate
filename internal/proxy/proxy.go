// Package proxy is front-end ① in the design: the one front-end that
// enforces, because every request kubectl makes passes through it. This
// build authenticates the session, refuses requests that try to choose
// their own identity, and forwards as the session's human.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/SaiPisey2/blastgate/internal/session"
	"github.com/SaiPisey2/blastgate/internal/store"
	"github.com/SaiPisey2/blastgate/internal/upstream"
)

const (
	HeaderAgent   = "Impersonate-Extra-Blastgate-Agent"
	HeaderSession = "Impersonate-Extra-Blastgate-Session"
)

type Authenticator interface {
	Authenticate(*http.Request) (store.Session, error)
}

type Proxy struct {
	auth Authenticator
	rp   *httputil.ReverseProxy
	log  *slog.Logger
}

type sessionKey struct{}

func New(auth Authenticator, up *upstream.Upstream, log *slog.Logger) *Proxy {
	p := &Proxy{auth: auth, log: log}
	p.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(up.URL)
			s := pr.In.Context().Value(sessionKey{}).(store.Session)
			h := pr.Out.Header
			// The session token authenticated the caller to blastgate. It
			// must not reach the API server; client-go's transport adds the
			// service-account token only when no Authorization is present.
			h.Del("Authorization")
			h.Set("Impersonate-User", s.Human)
			h.Set(HeaderAgent, s.Agent)
			h.Set(HeaderSession, s.ID)
		},
		Transport: switchTransport{normal: up.Normal, upgrade: up.Upgrade},
		// Watches, logs -f and exec stream; buffering them would hold the
		// first event until the stream ends.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.log.Warn("upstream error", "path", r.URL.Path, "err", err.Error())
			WriteStatus(w, http.StatusBadGateway, metav1.StatusReasonServiceUnavailable, "blastgate: the API server could not be reached")
		},
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	s, err := p.auth.Authenticate(r)
	if err != nil {
		if errors.Is(err, session.ErrUnauthenticated) {
			WriteStatus(w, http.StatusUnauthorized, metav1.StatusReasonUnauthorized, "Unauthorized")
			return
		}
		p.log.Error("session lookup failed", "err", err.Error())
		WriteStatus(w, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable, "blastgate: session lookup failed")
		return
	}
	// Go's server canonicalises header names, but compare lowercased anyway
	// so the check does not depend on that. X-Remote-* are the front-proxy
	// identity headers; the API server trusts them only from a front-proxy
	// client certificate blastgate does not hold, and they are refused here
	// so a future change of credential cannot turn them on silently.
	for k := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "impersonate-") || strings.HasPrefix(lk, "x-remote-") {
			p.log.Warn("refused client impersonation", "session", s.ID, "human", s.Human, "agent", s.Agent, "header", k)
			WriteStatus(w, http.StatusForbidden, metav1.StatusReasonForbidden, "blastgate: requests may not carry impersonation headers; the session already says who is acting")
			return
		}
	}
	rec := &recorder{ResponseWriter: w, status: http.StatusOK}
	p.rp.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), sessionKey{}, s)))
	// Path only: exec and attach carry the command in the query string,
	// and a command line is where passwords get typed.
	p.log.Info("request",
		"session", s.ID, "human", s.Human, "agent", s.Agent,
		"method", r.Method, "path", r.URL.Path,
		"status", rec.status, "upgrade", isUpgrade(r.Header),
		"ms", time.Since(start).Milliseconds())
}

// WriteStatus writes a Kubernetes Status, the only error body kubectl
// knows how to print.
func WriteStatus(w http.ResponseWriter, code int, reason metav1.StatusReason, msg string) {
	st := metav1.Status{
		TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
		Status:   metav1.StatusFailure,
		Message:  msg,
		Reason:   reason,
		Code:     int32(code),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(st)
}

type switchTransport struct{ normal, upgrade http.RoundTripper }

func (t switchTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if isUpgrade(r.Header) {
		return t.upgrade.RoundTrip(r)
	}
	return t.normal.RoundTrip(r)
}

func isUpgrade(h http.Header) bool {
	return httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade")
}

// recorder notes the status for the log. Unwrap lets
// http.ResponseController reach the real writer's Flush and Hijack, which
// ReverseProxy needs for streaming and for upgrades.
type recorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *recorder) WriteHeader(code int) {
	if !r.wrote {
		r.status, r.wrote = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(b)
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
