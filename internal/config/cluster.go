package config

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"k8s.io/client-go/tools/clientcmd"
)

const (
	maxClusterName = 63
	unnamedCluster = "unnamed cluster"
)

// checkClusterName refuses an operator-set name that would not render
// safely: the name is shown to approvers on a page that decides access
// grants, so a control or format rune (an ANSI escape, a bidi override)
// or an unbounded length is a config error, not something to clean up
// silently.
func checkClusterName(v string) error {
	if n := utf8.RuneCountInString(v); n > maxClusterName {
		return fmt.Errorf("BLASTGATE_CLUSTER_NAME is %d characters; at most %d", n, maxClusterName)
	}
	if strings.TrimSpace(v) == "" {
		return errors.New("BLASTGATE_CLUSTER_NAME is blank; unset it to use the kubeconfig's context name")
	}
	for _, r := range v {
		if unprintable(r) {
			return fmt.Errorf("BLASTGATE_CLUSTER_NAME %q may contain only printable characters", v)
		}
	}
	return nil
}

// unprintable is the one rule both paths share: control, format (bidi
// overrides), line and paragraph separators, NBSP and private-use runes
// all fail unicode.IsPrint, and Cf is named too so the intent survives a
// change to IsPrint.
func unprintable(r rune) bool {
	return !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r)
}

// cleanClusterName is the same rule applied to a name blastgate did not
// choose: a kubeconfig's context name is whatever its author typed, and
// refusing to start over it would be worse than showing a trimmed name.
func cleanClusterName(v string) string {
	var b strings.Builder
	n := 0
	for _, r := range v {
		if unprintable(r) {
			continue
		}
		if n == maxClusterName {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// ResolveClusterName is the name approvers see for the cluster a grant
// would reach: the operator's setting, else the upstream kubeconfig's
// current-context name, else "unnamed cluster" (always, in-cluster, where
// no context exists). It reads the file only; it never contacts a cluster.
// An env value the caller has not validated is cleaned rather than shown raw.
func ResolveClusterName(env, kubeconfigPath string, inCluster bool) string {
	if env != "" {
		if checkClusterName(env) == nil {
			return env
		}
		if c := cleanClusterName(env); c != "" {
			return c
		}
		return unnamedCluster
	}
	if inCluster || kubeconfigPath == "" {
		return unnamedCluster
	}
	cfg, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		return unnamedCluster
	}
	if c := cleanClusterName(cfg.CurrentContext); c != "" {
		return c
	}
	return unnamedCluster
}
