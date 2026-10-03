package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func writeKubeconfig(t *testing.T, currentContext string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kubeconfig")
	y := "apiVersion: v1\nkind: Config\ncurrent-context: " + `"` + currentContext + `"` + "\ncontexts:\n- name: " + `"` + currentContext + `"` + "\n  context: {cluster: c, user: u}\nclusters:\n- name: c\n  cluster: {server: \"https://127.0.0.1:1\"}\nusers:\n- name: u\n  user: {token: x}\n"
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClusterNameFromEnv(t *testing.T) {
	m := base()
	m["BLASTGATE_CLUSTER_NAME"] = "prod-eu"
	c, err := Load(env(m))
	if err != nil || c.ClusterName != "prod-eu" {
		t.Fatalf("got %q, %v", c.ClusterName, err)
	}
}

func TestEnvClusterNameOver63OrWithControlCharsIsAConfigError(t *testing.T) {
	for _, v := range []string{strings.Repeat("a", 64), "x\x1b[31m", "a‮b", "a\nb"} {
		m := base()
		m["BLASTGATE_CLUSTER_NAME"] = v
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%q was accepted", v)
		}
	}
	m := base()
	m["BLASTGATE_CLUSTER_NAME"] = strings.Repeat("é", 63)
	if _, err := Load(env(m)); err != nil {
		t.Errorf("63 runes refused: %v", err)
	}
}

func TestClusterNameFromKubeconfigIsCleaned(t *testing.T) {
	long := "\\u001b[31m\\u202e" + strings.Repeat("k", 80)
	got := ResolveClusterName("", writeKubeconfig(t, long), false)
	if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x202e) {
		t.Errorf("control or format rune survived: %q", got)
	}
	if n := utf8.RuneCountInString(got); n != 63 {
		t.Errorf("%d runes, want 63: %q", n, got)
	}
	if got := ResolveClusterName("", writeKubeconfig(t, "kind-dev"), false); got != "kind-dev" {
		t.Errorf("got %q", got)
	}
}

func TestUnnamedClusterWhenNothingIsSet(t *testing.T) {
	for name, got := range map[string]string{
		"no source":       ResolveClusterName("", "", false),
		"in cluster":      ResolveClusterName("", writeKubeconfig(t, "ignored"), true),
		"unreadable file": ResolveClusterName("", filepath.Join(t.TempDir(), "none"), false),
		"empty context":   ResolveClusterName("", writeKubeconfig(t, ""), false),
		"only control":    ResolveClusterName("", writeKubeconfig(t, "\\u001b\\u0007"), false),
	} {
		if got != "unnamed cluster" {
			t.Errorf("%s: %q", name, got)
		}
	}
	m := base()
	m["BLASTGATE_UPSTREAM_KUBECONFIG"] = ""
	m["BLASTGATE_UPSTREAM_IN_CLUSTER"] = "1"
	if c, err := Load(env(m)); err != nil || c.ClusterName != "unnamed cluster" {
		t.Errorf("in-cluster: %q, %v", c.ClusterName, err)
	}
}
