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
	"time"
)

var ErrInsecure = errors.New("insecure configuration")

type Config struct {
	Listen             string
	DataDir            string
	UpstreamKubeconfig string
	UpstreamInCluster  bool
	SigningKey         []byte
	TLSHosts           []string

	// Hold is how long a held request waits for a human before its ticket
	// is returned; ScoreBudget is how long scoring one write may take.
	Hold, ScoreBudget time.Duration
	// ApprovalTTL is how long an approval's token stays spendable.
	ApprovalTTL time.Duration
	// PolicyPath is the operator's policy file; "" means the built-in
	// default policy.
	PolicyPath string
}

const (
	minKeyLen      = 32
	minKeyDistinct = 10

	// kubectl's and the MCP SDK's own request timeouts are 60s. A hold
	// that outlasts them answers a client that has already gone, so its
	// ticket -- the approval ID the agent needs to ask for a decision --
	// is never seen.
	maxHold = 50 * time.Second
	// Scoring runs before the hold and again before an inline release, so
	// the two together must still end inside the client's 60s with a
	// margin for forwarding (ruling P1-R16).
	maxHoldPlusBudget = 55 * time.Second
	maxBudget         = 30 * time.Second
	maxApprovalTTL    = 24 * time.Hour
)

// Load is the configuration serve needs: everything LoadSigning reads,
// plus the hold window, score budget, policy file and upstream cluster.
func Load(getenv func(string) string) (Config, error) {
	c, err := LoadSigning(getenv)
	if err != nil {
		return Config{}, err
	}
	if c.Hold, err = duration(getenv, "BLASTGATE_HOLD", 45*time.Second, maxHold); err != nil {
		return Config{}, err
	}
	if c.ScoreBudget, err = duration(getenv, "BLASTGATE_SCORE_BUDGET", 5*time.Second, maxBudget); err != nil {
		return Config{}, err
	}
	if c.Hold+c.ScoreBudget > maxHoldPlusBudget {
		return Config{}, fmt.Errorf("BLASTGATE_HOLD (%s) plus BLASTGATE_SCORE_BUDGET (%s) must be at most %s: clients give up after 60s, and a held request's ticket must reach them first", c.Hold, c.ScoreBudget, maxHoldPlusBudget)
	}
	c.PolicyPath = getenv("BLASTGATE_POLICY")

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

// LoadSigning is the configuration a command that signs approvals needs
// (approve, deny): everything LoadLocal reads, plus a checked signing key
// and the approval token lifetime -- but not the upstream, which an
// approver's workstation has no reason to hold.
func LoadSigning(getenv func(string) string) (Config, error) {
	c, err := LoadLocal(getenv)
	if err != nil {
		return Config{}, err
	}
	key := getenv("BLASTGATE_SIGNING_KEY")
	if err := checkKey(key); err != nil {
		return Config{}, err
	}
	c.SigningKey = []byte(key)
	if c.ApprovalTTL, err = duration(getenv, "BLASTGATE_APPROVAL_TTL", 15*time.Minute, maxApprovalTTL); err != nil {
		return Config{}, err
	}
	return c, nil
}

// duration reads a positive duration no longer than max. Zero is refused
// rather than read as "off": a zero hold would ticket every held write
// without waiting, and a zero budget would score nothing, so every write
// would hold -- neither is a setting anyone means.
func duration(getenv func(string) string, name string, def, max time.Duration) (time.Duration, error) {
	v := getenv(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a duration (for example %s)", name, v, def)
	}
	if d <= 0 || d > max {
		return 0, fmt.Errorf("%s %s must be more than 0 and at most %s", name, d, max)
	}
	return d, nil
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
