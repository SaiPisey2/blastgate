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
	utilnet "k8s.io/apimachinery/pkg/util/net"

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

// outcomeUnknown marks a request whose client left before the API server
// answered. The server may have acted anyway (a create can be committed
// before the reply is lost), so it is recorded as neither success nor
// failure.
const outcomeUnknown = "client cancelled; outcome unknown"

type requestKey struct{}

// request travels in the context so the ErrorHandler can name who acted
// and tell ServeHTTP's log line what happened.
type request struct {
	s store.Session
	// path is the client's, kept because the ErrorHandler sees the
	// rewritten request, whose path gains any upstream prefix.
	path      string
	cancelled bool
}

func New(auth Authenticator, up *upstream.Upstream, log *slog.Logger) *Proxy {
	p := &Proxy{auth: auth, log: log}
	p.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(up.URL)
			s := pr.In.Context().Value(requestKey{}).(*request).s
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
		// first event until the stream ends. The standard library already
		// flushes unknown-length responses at once, so this guards the
		// streams that declare a length.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			rq := r.Context().Value(requestKey{}).(*request)
			who := []any{"session", rq.s.ID, "human", rq.s.Human, "agent", rq.s.Agent, "method", r.Method, "path", rq.path}
			if errors.Is(err, context.Canceled) {
				// Nobody is listening for a Status, and a 502 in the log
				// would claim a failure the API server may not have had.
				rq.cancelled = true
				p.log.Warn(outcomeUnknown, who...)
				return
			}
			p.log.Warn("upstream error", append(who, "err", err.Error())...)
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
	if k, ok := impersonation(r); ok {
		// The header name only: its value is whoever the caller tried to
		// become, and need not be a harmless string.
		p.log.Warn("refused client impersonation", "session", s.ID, "human", s.Human, "agent", s.Agent, "header", k)
		WriteStatus(w, http.StatusForbidden, metav1.StatusReasonForbidden, "blastgate: requests may not carry impersonation headers; the session already says who is acting")
		return
	}
	rec := &recorder{ResponseWriter: w, status: http.StatusOK}
	rq := &request{s: s, path: r.URL.Path}
	// Deferred because ReverseProxy panics with ErrAbortHandler when the
	// client leaves mid-stream; a log call after it would be skipped for
	// every watch or logs -f the client stops.
	defer func() {
		v := recover()
		// Path only: exec and attach carry the command in the query string,
		// and a command line is where passwords get typed.
		attrs := []any{"session", s.ID, "human", s.Human, "agent", s.Agent,
			"method", r.Method, "path", r.URL.Path}
		if rq.cancelled {
			attrs = append(attrs, "outcome", outcomeUnknown)
		} else {
			attrs = append(attrs, "status", rec.status)
		}
		if v != nil {
			attrs = append(attrs, "aborted", true)
		}
		attrs = append(attrs, "upgrade", isUpgrade(r.Header), "ms", time.Since(start).Milliseconds())
		p.log.Info("request", attrs...)
		if v != nil {
			// http.Server still has to see the panic to drop the
			// connection instead of ending the stream as if complete.
			panic(v)
		}
	}()
	p.rp.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), requestKey{}, rq)))
}

// impersonation reports the first header, or declared trailer, that tries
// to choose an identity. Go's server canonicalises header names, but the
// comparison is lowercased anyway so the check does not depend on that.
// X-Remote-* are the front-proxy identity headers; the API server trusts
// them only from a front-proxy client certificate blastgate does not hold,
// and they are refused here so a future change of credential cannot turn
// them on silently. Trailers are checked because ReverseProxy forwards
// them: a chunked request could otherwise send one after the body.
func impersonation(r *http.Request) (string, bool) {
	names := make([]string, 0, len(r.Header)+len(r.Trailer))
	for k := range r.Header {
		names = append(names, k)
	}
	for k := range r.Trailer {
		names = append(names, k)
	}
	// Without chunking the server leaves Trailer as a plain header.
	for _, v := range r.Header["Trailer"] {
		for _, k := range strings.Split(v, ",") {
			names = append(names, strings.TrimSpace(k))
		}
	}
	for _, k := range names {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "impersonate-") || strings.HasPrefix(lk, "x-remote-") {
			return k, true
		}
	}
	return "", false
}

// WriteStatus writes a Kubernetes Status, the only error body kubectl
// knows how to print, and also copies msg into a Warning header, which
// client-go prints. kubectl's first requests are discovery, which reads a
// failed response with Raw() and never decodes the body: without the
// Warning, a refusal there prints as "Error from server (Forbidden):
// unknown" -- the same thing kubectl prints for the API server's own
// refusals on discovery. Because msg is echoed into a header as well as
// the body, callers must pass only constant blastgate text, never
// anything derived from the request or the session.
func WriteStatus(w http.ResponseWriter, code int, reason metav1.StatusReason, msg string) {
	// A message a Warning cannot carry (control characters, invalid UTF-8)
	// still goes in the body; it only loses the header.
	if wh, err := utilnet.NewWarningHeader(299, "-", msg); err == nil {
		w.Header().Add("Warning", wh)
	}
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
