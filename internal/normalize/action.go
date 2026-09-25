// Package normalize turns an HTTP request to the Kubernetes API into the
// one Action shape every front-end shares (design §3.2). It uses the API
// server's own request parser, so blastgate and the cluster agree on what
// verb, resource and subresource a path means -- a hand-written parser
// that disagreed with the server would score one thing and forward
// another.
package normalize

import (
	"fmt"
	"net/http"
	"sort"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/endpoints/request"
)

type Principal struct{ Session, Human, Agent string }

type Action struct {
	Verb        string              `json:"verb"`
	Group       string              `json:"group"`
	Version     string              `json:"version"`
	Resource    string              `json:"resource"`
	Subresource string              `json:"subresource"`
	Namespace   string              `json:"namespace"`
	Name        string              `json:"name"`
	PatchType   string              `json:"patchType,omitempty"`
	Query       map[string][]string `json:"query,omitempty"`
	Principal   Principal           `json:"principal"`
	Source      string              `json:"source"`
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
	info, err := infoFactory.NewRequestInfo(r)
	if err != nil {
		return Action{}, fmt.Errorf("parsing request: %w", err)
	}
	a := Action{Principal: p, Source: "proxy"}
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
	// RequestInfoFactory reports "delete namespace demo" with the name in
	// Name and the namespace in Namespace as well; the target is the
	// cluster-scoped Namespace object.
	if a.Resource == "namespaces" && a.Subresource == "" {
		a.Namespace = ""
	}
	if a.Verb == "patch" {
		a.PatchType = r.Header.Get("Content-Type")
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

func (a Action) IsRead() bool {
	switch a.Verb {
	case "get", "list", "watch":
		return true
	}
	return false
}
