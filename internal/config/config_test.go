package config

import (
	"errors"
	"strings"
	"testing"
)

const goodKey = "3f9a1c07d24be85f6a0913c7e2d84b5f70a6c31e9d28f4b1"

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func base() map[string]string {
	return map[string]string{
		"BLASTGATE_DATA_DIR":            "/tmp/bg",
		"BLASTGATE_SIGNING_KEY":         goodKey,
		"BLASTGATE_UPSTREAM_KUBECONFIG": "/tmp/upstream.kubeconfig",
	}
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(base()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8443" {
		t.Errorf("listen = %q", c.Listen)
	}
	if strings.Join(c.TLSHosts, ",") != "127.0.0.1,localhost" {
		t.Errorf("tls hosts = %v", c.TLSHosts)
	}
	if string(c.SigningKey) != goodKey || c.UpstreamKubeconfig != "/tmp/upstream.kubeconfig" {
		t.Errorf("config = %+v", c)
	}
}

func TestSigningKeyRefusals(t *testing.T) {
	for name, key := range map[string]string{
		"missing":  "",
		"short":    "abc123",
		"repeated": strings.Repeat("changeme", 5),
		"one-byte": strings.Repeat("a", 64),
	} {
		t.Run(name, func(t *testing.T) {
			m := base()
			m["BLASTGATE_SIGNING_KEY"] = key
			if _, err := Load(env(m)); !errors.Is(err, ErrInsecure) {
				t.Errorf("err = %v, want ErrInsecure", err)
			}
		})
	}
}

// A hex key of 32 random bytes must never be rejected as weak.
func TestHexKeyFromOpensslIsAccepted(t *testing.T) {
	m := base()
	m["BLASTGATE_SIGNING_KEY"] = "9c2e0f7b41d8a36e5f1c9b0a7d4e2f8c6b3a1d0e9f7c5b2a4e6d8f0a1c3b5e7d"
	if _, err := Load(env(m)); err != nil {
		t.Errorf("err = %v", err)
	}
}

func TestUpstreamMustBeExplicit(t *testing.T) {
	m := base()
	delete(m, "BLASTGATE_UPSTREAM_KUBECONFIG")
	_, err := Load(env(m))
	if err == nil || !strings.Contains(err.Error(), "default kubeconfig") {
		t.Errorf("err = %v, want a refusal explaining the default kubeconfig is never used", err)
	}
}

func TestUpstreamCannotBeBoth(t *testing.T) {
	m := base()
	m["BLASTGATE_UPSTREAM_IN_CLUSTER"] = "1"
	if _, err := Load(env(m)); err == nil {
		t.Error("both a kubeconfig and in-cluster were accepted")
	}
}

func TestInClusterAlone(t *testing.T) {
	m := base()
	delete(m, "BLASTGATE_UPSTREAM_KUBECONFIG")
	m["BLASTGATE_UPSTREAM_IN_CLUSTER"] = "1"
	c, err := Load(env(m))
	if err != nil || !c.UpstreamInCluster {
		t.Errorf("c = %+v, err = %v", c, err)
	}
}

func TestNonLoopbackListenIsOptIn(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8443", ":8443", "10.0.0.5:8443", "[::]:8443"} {
		m := base()
		m["BLASTGATE_LISTEN"] = addr
		if _, err := Load(env(m)); !errors.Is(err, ErrInsecure) {
			t.Errorf("%s: err = %v, want ErrInsecure", addr, err)
		}
		m["BLASTGATE_ALLOW_REMOTE"] = "1"
		if _, err := Load(env(m)); err != nil {
			t.Errorf("%s with opt-in: err = %v", addr, err)
		}
	}
}

func TestLoopbackForms(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:9000", "localhost:9000", "[::1]:9000"} {
		m := base()
		m["BLASTGATE_LISTEN"] = addr
		if _, err := Load(env(m)); err != nil {
			t.Errorf("%s: err = %v", addr, err)
		}
	}
}

func TestDataDirRequired(t *testing.T) {
	m := base()
	delete(m, "BLASTGATE_DATA_DIR")
	if _, err := LoadLocal(env(m)); err == nil {
		t.Error("missing data dir accepted")
	}
}

func TestLoadLocalNeedsNoKeyOrUpstream(t *testing.T) {
	c, err := LoadLocal(env(map[string]string{"BLASTGATE_DATA_DIR": "/tmp/bg"}))
	if err != nil || c.DataDir != "/tmp/bg" {
		t.Errorf("c = %+v, err = %v", c, err)
	}
}

func TestTLSHostsParsed(t *testing.T) {
	m := base()
	m["BLASTGATE_TLS_HOSTS"] = " 127.0.0.1, gate.internal ,,"
	c, err := Load(env(m))
	if err != nil || strings.Join(c.TLSHosts, ",") != "127.0.0.1,gate.internal" {
		t.Errorf("hosts = %v, err = %v", c.TLSHosts, err)
	}
}
