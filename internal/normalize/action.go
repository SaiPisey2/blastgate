// Package normalize turns an HTTP request to the Kubernetes API into the
// one Action shape every front-end shares (design §3.2). It uses the API
// server's own request parser, so blastgate and the cluster agree on what
// verb, resource and subresource a path means -- a hand-written parser
// that disagreed with the server would score one thing and forward
// another.
package normalize

import (
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/http/httpguts"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/endpoints/request"
)

type Principal struct{ Session, Human, Agent string }

type Action struct {
	Verb        string `json:"verb"`
	Group       string `json:"group"`
	Version     string `json:"version"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	// Path is the request's escaped URL path. RequestInfo does not expose
	// the sub-path after a proxy subresource (pods/x/proxy/<anything>,
	// services/x/proxy/..., nodes/x/proxy/...) -- two different proxied
	// endpoints otherwise share one Action, so an approval for one would
	// silently cover the other. Kept for every request, not only proxy
	// ones, since the path is what fully determines the target.
	Path string `json:"path"`
	// RawQuery is the full, unparsed query string. Only set for a proxy
	// subresource: the proxy target is chosen by the backend, from
	// whatever it finds in the query, not only from the semantic
	// parameters blastgate otherwise recognises -- the same sub-path with
	// a different query can be a different backend endpoint.
	RawQuery string `json:"rawQuery,omitempty"`
	// Upgrade is set when the request asks to switch protocols
	// (Connection: Upgrade). An upgraded connection is a bidirectional
	// stream whatever its verb, so it is never a read, and it is part of
	// the digest: approving a plain GET must not also approve the stream.
	Upgrade   bool                `json:"upgrade,omitempty"`
	PatchType string              `json:"patchType,omitempty"`
	Query     map[string][]string `json:"query,omitempty"`
	Principal Principal           `json:"principal"`
	Source    string              `json:"source"`
}

var infoFactory = &request.RequestInfoFactory{
	// k8s.io/apiserver@v0.37.1's RequestInfoFactory still takes the old
	// map-based sets.String, not the generic sets.Set[string]; sets.New
	// does not compile against it.
	APIPrefixes:          sets.NewString("api", "apis"),
	GrouplessAPIPrefixes: sets.NewString("api"),
}

// semanticQuery are the parameters that change what a request does. The
// rest (pretty, timeout, resourceVersion for a read, ...) only change how
// the answer is presented or waited for, and must not make an identical
// retry look like a different request.
var semanticQuery = []string{
	"dryRun", "fieldManager", "fieldValidation", "force", "propagationPolicy",
	"gracePeriodSeconds", "orphanDependents", "labelSelector", "fieldSelector",
	"command", "container", "stdin", "stdout", "stderr", "tty", "ports",
}

func FromRequest(r *http.Request, p Principal) (Action, error) {
	if err := checkSegments(r.URL.EscapedPath()); err != nil {
		return Action{}, err
	}
	info, err := infoFactory.NewRequestInfo(r)
	if err != nil {
		return Action{}, fmt.Errorf("parsing request: %w", err)
	}
	a := Action{Principal: p, Source: "proxy", Path: r.URL.EscapedPath()}
	// The same test the proxy's transport switch uses: whatever it would
	// forward as an upgrade, the gate must treat as one.
	a.Upgrade = httpguts.HeaderValuesContainsToken(r.Header["Connection"], "Upgrade")
	if !info.IsResourceRequest {
		// Discovery, /version, /openapi: harmless to read, meaningless to
		// write. A write here is nothing this build can score.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			return Action{}, fmt.Errorf("non-resource %s is not understood", r.Method)
		}
		a.Verb = "get"
		return a, nil
	}
	a.Verb, a.Group, a.Version = info.Verb, info.APIGroup, info.APIVersion
	a.Resource, a.Subresource = info.Resource, info.Subresource
	a.Namespace, a.Name = info.Namespace, info.Name
	if a.Resource == "pods" && streamSubresources[a.Subresource] {
		// kubectl tries WebSocket (GET, parsed as "get") and falls back to
		// SPDY (POST, "create") for one command. The API server authorises
		// both as create; so does blastgate, or the two attempts digest
		// differently and one command leaves two pending approvals --
		// denying the one the agent reported would leave its twin live.
		a.Verb = "create"
	}
	// RequestInfoFactory reports "delete namespace demo" with the name in
	// Name and the namespace in Namespace as well; the target is the
	// cluster-scoped Namespace object.
	if a.Resource == "namespaces" && a.Subresource == "" {
		a.Namespace = ""
	}
	if a.Subresource == "proxy" {
		// RequestInfo has no field for the sub-path or query after
		// .../proxy/ -- the backend the proxy dials is chosen from both,
		// so both must be part of what the digest binds an approval to.
		a.RawQuery = r.URL.RawQuery
	}
	if a.Verb == "patch" {
		a.PatchType = normalizePatchType(r.Header.Get("Content-Type"))
	}
	q := r.URL.Query()
	for _, k := range semanticQuery {
		if v, ok := q[k]; ok {
			if a.Query == nil {
				a.Query = map[string][]string{}
			}
			vs := append([]string(nil), v...)
			// ports and command keep their order: "psql -c x" and
			// "-c psql x" are different commands.
			if k != "command" && k != "ports" {
				sort.Strings(vs)
			}
			a.Query[k] = vs
		}
	}
	return a, nil
}

// streamSubresources are the pod subresources opened as a stream over
// either transport.
var streamSubresources = map[string]bool{"exec": true, "attach": true, "portforward": true}

// checkSegments refuses a path with a ".", ".." or empty segment, escaped
// or not. The parser takes the path as it is, but a server or proxy that
// cleans paths would resolve pods/../secrets (or collapse a//b) to a
// different object than the one parsed -- and a read is forwarded
// unscored, so the parse is all that stands between it and the wrong
// object.
func checkSegments(escaped string) error {
	// One trailing slash is not refused: a cleaner resolves .../web/ to
	// .../web, the same object the parser reads, and apiPath already
	// accepts it (TestAPIPathAgreesWithNormalize). "/" alone is the root.
	trimmed := strings.TrimSuffix(strings.TrimPrefix(escaped, "/"), "/")
	if trimmed == "" && (escaped == "/" || escaped == "") {
		return nil
	}
	for _, seg := range strings.Split(trimmed, "/") {
		u, err := url.PathUnescape(seg)
		if err != nil {
			return fmt.Errorf("path segment not decodable: %w", err)
		}
		if u == "" || u == "." || u == ".." {
			return fmt.Errorf("path has an empty, \".\" or \"..\" segment")
		}
	}
	return nil
}

// normalizePatchType strips parameters (e.g. "; charset=utf-8") from a
// Content-Type so the same patch type sent with different parameters still
// binds to the same digest. A header mime can't parse is kept verbatim --
// it's not one of the four patch types anyway, so it can't collide with one.
func normalizePatchType(contentType string) string {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return contentType
	}
	return mediaType
}

// interactiveSubresources reach an arbitrary backend or open a bidirectional
// stream, never merely reading a stored object -- kubectl's exec (1.30+)
// and port-forward (1.31+) are a WebSocket opened with an HTTP GET, so
// RequestInfoFactory reports verb "get" for them exactly as it would for a
// read. Controller ruling P1-R6: IsRead must not trust the verb alone here.
var interactiveSubresources = map[string]bool{
	"exec":        true,
	"attach":      true,
	"portforward": true,
	"proxy":       true,
}

func (a Action) IsRead() bool {
	if a.Upgrade || interactiveSubresources[a.Subresource] {
		return false
	}
	switch a.Verb {
	case "get", "list", "watch":
		return true
	}
	return false
}
