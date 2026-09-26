// Package config reads blastgate's configuration from the environment and
// refuses the configurations that would make it unsafe to run. blastgate
// holds the right to impersonate people on a cluster; every default here
// is the one that fails closed.
package config

import (
	"errors"
	"fmt"
	"net"
	"slices"
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

	// AdminListen is the approver UI and its API; WebhookListen is the
	// observe-only admission webhook, "" (the default) meaning off.
	AdminListen, WebhookListen string
	// WebhookClientCA is a PEM file of the CAs whose client certificates
	// the webhook listener requires; "" asks for no client certificate.
	WebhookClientCA string
	// BypassIgnore are the username prefixes whose writes the webhook
	// never records: Kubernetes' own components.
	BypassIgnore []string
	// BypassIncludeNoise makes the webhook record Lease and Event writes,
	// which it skips by default (BLASTGATE_BYPASS_INCLUDE_NOISE=1).
	BypassIncludeNoise bool
}

const (
	minKeyLen      = 32
	minKeyDistinct = 10

	// kubectl's and the MCP SDK's own request timeouts are 60s. A hold
	// that outlasts them answers a client that has already gone, so its
	// ticket -- the approval ID the agent needs to ask for a decision --
	// is never seen.
	maxHold = 50 * time.Second
	// The worst case after the hold window is a re-score plus a snapshot,
	// each itself bounded by ScoreBudget, before the ticket is answered --
	// so the hold and *two* score budgets together must still end inside
	// the client's 60s with a margin for forwarding (ruling P1-R16).
	maxHoldPlusBudget = 55 * time.Second
	maxBudget         = 30 * time.Second
	maxApprovalTTL    = 24 * time.Hour
)

// defaultBypassIgnore matches webhook.DefaultIgnore (a test in cmd/blastgate
// pins the two together); config does not import the webhook, which would
// pull the Kubernetes API types into every command's configuration.
var defaultBypassIgnore = []string{"system:node:", "system:kube-", "system:serviceaccount:kube-system:", "system:apiserver"}

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
	if c.Hold+2*c.ScoreBudget > maxHoldPlusBudget {
		return Config{}, fmt.Errorf("BLASTGATE_HOLD (%s) plus twice BLASTGATE_SCORE_BUDGET (%s) must be at most %s: clients give up after 60s, and a held request's re-score and snapshot must both fit before its ticket reaches them", c.Hold, c.ScoreBudget, maxHoldPlusBudget)
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
	if err := loadListeners(&c, getenv); err != nil {
		return Config{}, err
	}
	return c, nil
}

// loadListeners reads the admin and webhook addresses, the webhook's
// client CA and its ignore list. Only serve reads them: a command that
// signs or lists has no listener to get wrong.
func loadListeners(c *Config, getenv func(string) string) error {
	c.AdminListen = "127.0.0.1:8444"
	if v := getenv("BLASTGATE_ADMIN_LISTEN"); v != "" {
		c.AdminListen = v
	}
	c.WebhookListen = getenv("BLASTGATE_WEBHOOK_LISTEN")
	remote := getenv("BLASTGATE_ALLOW_REMOTE") == "1"
	if err := checkListen("BLASTGATE_ADMIN_LISTEN", c.AdminListen, remote,
		"the admin listener decides held writes"); err != nil {
		return err
	}
	addrs := []struct{ name, addr string }{{"BLASTGATE_LISTEN", c.Listen}, {"BLASTGATE_ADMIN_LISTEN", c.AdminListen}}
	if c.WebhookListen != "" {
		if err := checkListen("BLASTGATE_WEBHOOK_LISTEN", c.WebhookListen, remote,
			"the webhook writes bypass records"); err != nil {
			return err
		}
		addrs = append(addrs, struct{ name, addr string }{"BLASTGATE_WEBHOOK_LISTEN", c.WebhookListen})
	}
	// Two listeners on one address would fail to bind at start-up with
	// "address already in use"; saying which two settings collide beats
	// leaving the operator to work it out from the port.
	for i := range addrs {
		for j := i + 1; j < len(addrs); j++ {
			if sameAddress(addrs[i].addr, addrs[j].addr) {
				return fmt.Errorf("%s %q and %s %q are the same address; each listener needs its own", addrs[i].name, addrs[i].addr, addrs[j].name, addrs[j].addr)
			}
		}
	}
	c.WebhookClientCA = getenv("BLASTGATE_WEBHOOK_CLIENT_CA")
	if c.WebhookClientCA != "" && c.WebhookListen == "" {
		// A client CA with no webhook reads like protection that is on;
		// it protects nothing, and the webhook the operator meant to lock
		// down is not running either.
		return errors.New("BLASTGATE_WEBHOOK_CLIENT_CA is set but BLASTGATE_WEBHOOK_LISTEN is not; the webhook is off")
	}
	// A copy, so a caller appending to its list never edits the default.
	c.BypassIgnore = slices.Clone(defaultBypassIgnore)
	if v := getenv("BLASTGATE_BYPASS_IGNORE"); v != "" {
		// Commas and spaces alone would ignore nothing, and every
		// ReplicaSet scale and kubelet status write would become a bypass
		// record; that is a typo, not a setting.
		if c.BypassIgnore = splitList(v); len(c.BypassIgnore) == 0 {
			return fmt.Errorf("BLASTGATE_BYPASS_IGNORE %q names no username prefixes", v)
		}
	}
	// Only 0 or 1: "true" or "yes" quietly meaning off would leave the
	// operator believing the Lease and Event writes were being recorded.
	switch v := getenv("BLASTGATE_BYPASS_INCLUDE_NOISE"); v {
	case "", "0":
	case "1":
		c.BypassIncludeNoise = true
	default:
		return fmt.Errorf("BLASTGATE_BYPASS_INCLUDE_NOISE %q must be 1 (record Lease and Event writes) or 0", v)
	}
	return nil
}

// checkListen applies BLASTGATE_LISTEN's rule to another listener: a
// loopback address, or an explicit BLASTGATE_ALLOW_REMOTE=1.
func checkListen(name, addr string, remote bool, why string) error {
	loop, err := isLoopback(addr)
	if err != nil {
		return fmt.Errorf("%s %q: %w", name, addr, err)
	}
	if !loop && !remote {
		return fmt.Errorf("%w: %s %q is not a loopback address; %s, so listening beyond this machine is opt-in (BLASTGATE_ALLOW_REMOTE=1)", ErrInsecure, name, addr, why)
	}
	return nil
}

// sameAddress reports two listen addresses that cannot both bind: the
// same port on the same host, on hosts that are both loopback, or where
// either binds every address. Port 0 (pick any) never collides.
func sameAddress(a, b string) bool {
	ha, pa, err1 := net.SplitHostPort(a)
	hb, pb, err2 := net.SplitHostPort(b)
	if err1 != nil || err2 != nil || pa != pb || pa == "0" {
		return false
	}
	if ha == hb || anyHost(ha) || anyHost(hb) {
		return true
	}
	la, _ := isLoopback(a)
	lb, _ := isLoopback(b)
	return la && lb
}

func anyHost(h string) bool {
	if h == "" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsUnspecified()
}

// splitList is a comma list with blanks trimmed and empty entries dropped.
func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
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
		c.TLSHosts = splitList(v)
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
