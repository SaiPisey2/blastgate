// Package upstream is how blastgate reaches the real API server: with its
// own service-account credentials, which carry nothing but the right to
// impersonate. Each request is sent as the session's human by headers the
// proxy sets, so the credential here never decides what a request may do.
package upstream

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/SaiPisey2/blastgate/internal/config"
)

type Upstream struct {
	URL     *url.URL
	Normal  http.RoundTripper
	Upgrade http.RoundTripper
	// Config is what the engine builds its read-only scoring clients from.
	// It carries only the service account's credential, never a human's,
	// so scoring reads what the service account may read and writes nothing.
	Config *rest.Config
}

func Load(c config.Config) (*Upstream, error) {
	var cfg *rest.Config
	var err error
	switch {
	case c.UpstreamInCluster:
		cfg, err = rest.InClusterConfig()
	case c.UpstreamKubeconfig != "":
		// BuildConfigFromFlags with a non-empty path loads exactly that
		// file. With an empty path it would fall through to other sources,
		// which config.Load already refuses to let happen.
		cfg, err = clientcmd.BuildConfigFromFlags("", c.UpstreamKubeconfig)
	default:
		return nil, errors.New("no upstream configured")
	}
	if err != nil {
		return nil, fmt.Errorf("loading upstream: %w", err)
	}
	return FromConfig(cfg)
}

func FromConfig(cfg *rest.Config) (*Upstream, error) {
	im := cfg.Impersonate
	if im.UserName != "" || im.UID != "" || len(im.Groups) > 0 || len(im.Extra) > 0 {
		// Stacked impersonation would forward as whoever this config names,
		// not the session's human, and the cluster's audit log would say so.
		return nil, fmt.Errorf("the upstream kubeconfig already impersonates %q; blastgate sets impersonation per request", im.UserName)
	}
	u, err := url.Parse(cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("upstream host %q: %w", cfg.Host, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("upstream %q is not https; blastgate forwards a service-account credential and will not send it in the clear", cfg.Host)
	}
	normal, err := rest.TransportFor(cfg)
	if err != nil {
		return nil, err
	}
	// client-go only configures HTTP/2 when NextProtos is empty or lists
	// h2, so pinning it to http/1.1 yields a transport that can carry the
	// Connection: Upgrade exec and port-forward depend on.
	up := rest.CopyConfig(cfg)
	up.NextProtos = []string{"http/1.1"}
	upgrade, err := rest.TransportFor(up)
	if err != nil {
		return nil, err
	}
	return &Upstream{URL: u, Normal: normal, Upgrade: upgrade, Config: cfg}, nil
}
