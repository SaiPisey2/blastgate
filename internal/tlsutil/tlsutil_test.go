package tlsutil

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func verify(t *testing.T, caPEM []byte, leaf []byte, host string) error {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("bad CA PEM")
	}
	c, err := x509.ParseCertificate(leaf)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Verify(x509.VerifyOptions{Roots: pool, DNSName: host})
	return err
}

func TestCreatesACAAndACertForTheHosts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	cert, caPEM, err := LoadOrCreate(dir, []string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"127.0.0.1", "localhost"} {
		if err := verify(t, caPEM, cert.Certificate[0], h); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
	if err := verify(t, caPEM, cert.Certificate[0], "evil.example"); err == nil {
		t.Error("certificate verified for a host it was not issued for")
	}
}

func TestKeysAreOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	if _, _, err := LoadOrCreate(dir, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"ca.key", "server.key"} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", f, st.Mode().Perm())
		}
	}
	st, _ := os.Stat(dir)
	if st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", st.Mode().Perm())
	}
}

// Every kubeconfig handed out embeds the CA. Regenerating it on restart
// would break every session's kubeconfig at once.
func TestSecondCallKeepsTheCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	_, a, err := LoadOrCreate(dir, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := LoadOrCreate(dir, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("CA changed between calls")
	}
}

func TestANewHostReissuesTheServerCertUnderTheSameCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	_, ca1, err := LoadOrCreate(dir, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	cert, ca2, err := LoadOrCreate(dir, []string{"127.0.0.1", "gate.internal"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca1, ca2) {
		t.Error("CA changed")
	}
	if err := verify(t, ca2, cert.Certificate[0], "gate.internal"); err != nil {
		t.Errorf("new host not covered: %v", err)
	}
}
