// Package config reads blastgate's configuration from the environment and
// refuses the configurations that would make it unsafe to run. blastgate
// holds the right to impersonate people on a cluster; every default here
// is the one that fails closed.
package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

var ErrInsecure = errors.New("insecure configuration")

type Config struct {
	Listen             string
	DataDir            string
	UpstreamKubeconfig string
	UpstreamInCluster  bool
	SigningKey         []byte
	TLSHosts           []string
}

const (
	minKeyLen      = 32
	minKeyDistinct = 10
)

// Load is the configuration serve needs: everything LoadLocal reads, plus
// the signing key and the upstream cluster.
func Load(getenv func(string) string) (Config, error) {
	c, err := LoadLocal(getenv)
	if err != nil {
		return Config{}, err
	}
	key := getenv("BLASTGATE_SIGNING_KEY")
	if err := checkKey(key); err != nil {
		return Config{}, err
	}
	// Nothing signs with the key yet: it is reserved for the approval
	// tokens of the next phase, and required now so a deployment made
	// today does not start failing when that lands.
	c.SigningKey = []byte(key)

	path := getenv("BLASTGATE_UPSTREAM_KUBECONFIG")
	inCluster := getenv("BLASTGATE_UPSTREAM_IN_CLUSTER") == "1"
	switch {
	case path != "" && inCluster:
		return Config{}, errors.New("set BLASTGATE_UPSTREAM_KUBECONFIG or BLASTGATE_UPSTREAM_IN_CLUSTER=1, not both")
	case path == "" && !inCluster:
		// The default kubeconfig on a workstation is a human's own
		// credentials for whatever cluster they last used -- often a real
		// one. blastgate forwarding with those would make every agent that
		// person, with every right they hold, which is the thing it exists
		// to prevent.
		return Config{}, errors.New("set BLASTGATE_UPSTREAM_KUBECONFIG to the service-account kubeconfig blastgate forwards with, or BLASTGATE_UPSTREAM_IN_CLUSTER=1 inside a pod; the default kubeconfig is never used")
	}
	c.UpstreamKubeconfig, c.UpstreamInCluster = path, inCluster
	return c, nil
}

// LoadLocal is the configuration a local command such as `session new`
// needs: where the data lives and what address kubectl will be pointed at.
func LoadLocal(getenv func(string) string) (Config, error) {
	c := Config{Listen: "127.0.0.1:8443", TLSHosts: []string{"127.0.0.1", "localhost"}}
	if v := getenv("BLASTGATE_LISTEN"); v != "" {
		c.Listen = v
	}
	c.DataDir = getenv("BLASTGATE_DATA_DIR")
	if c.DataDir == "" {
		return Config{}, errors.New("BLASTGATE_DATA_DIR is not set")
	}
	if v := getenv("BLASTGATE_TLS_HOSTS"); v != "" {
		var hosts []string
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hosts = append(hosts, h)
			}
		}
		c.TLSHosts = hosts
	}
	loop, err := isLoopback(c.Listen)
	if err != nil {
		return Config{}, fmt.Errorf("BLASTGATE_LISTEN %q: %w", c.Listen, err)
	}
	if !loop && getenv("BLASTGATE_ALLOW_REMOTE") != "1" {
		return Config{}, fmt.Errorf("%w: BLASTGATE_LISTEN %q is not a loopback address; blastgate can impersonate people on the cluster, so listening beyond this machine is opt-in (BLASTGATE_ALLOW_REMOTE=1)", ErrInsecure, c.Listen)
	}
	return c, nil
}

// checkKey refuses a missing, short or low-entropy key. The distinct-byte
// floor catches a repeated word ("changemechangeme…") without rejecting a
// hex key: 64 hex characters from `openssl rand -hex 32` show ~16 distinct
// bytes, and even 32 of them fall below 10 with negligible probability.
func checkKey(k string) error {
	if k == "" {
		return fmt.Errorf("%w: BLASTGATE_SIGNING_KEY is not set (generate one with: openssl rand -hex 32)", ErrInsecure)
	}
	if len(k) < minKeyLen {
		return fmt.Errorf("%w: BLASTGATE_SIGNING_KEY must be at least %d bytes", ErrInsecure, minKeyLen)
	}
	seen := map[byte]bool{}
	for i := 0; i < len(k); i++ {
		seen[k[i]] = true
	}
	if len(seen) < minKeyDistinct {
		return fmt.Errorf("%w: BLASTGATE_SIGNING_KEY looks like a repeated word, not a random key", ErrInsecure)
	}
	return nil
}

func isLoopback(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, err
	}
	if host == "localhost" {
		return true, nil
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback(), nil
}
