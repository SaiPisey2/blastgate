// Package tlsutil keeps a small local certificate authority and the
// serving certificate kubectl sees when it talks to blastgate. The CA is
// created once and kept: every session kubeconfig embeds it, so replacing
// it would break every session at once. The serving certificate is
// reissued whenever it no longer covers the configured hosts or is within
// 30 days of expiry.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const renewBefore = 30 * 24 * time.Hour

func LoadOrCreate(dir string, hosts []string) (tls.Certificate, []byte, error) {
	if len(hosts) == 0 {
		return tls.Certificate{}, nil, errors.New("no TLS hosts configured")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, nil, err
	}
	// MkdirAll leaves an existing directory's mode alone.
	if err := os.Chmod(dir, 0o700); err != nil {
		return tls.Certificate{}, nil, err
	}
	ca, caKey, caPEM, err := loadOrCreateCA(dir)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("certificate authority: %w", err)
	}
	certPEM, keyPEM, err := read(dir, "server")
	if err == nil && usable(certPEM, ca, hosts) {
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		return pair, caPEM, err
	}
	certPEM, keyPEM, err = issue(ca, caKey, hosts)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("serving certificate: %w", err)
	}
	if err := write(dir, "server", certPEM, keyPEM); err != nil {
		return tls.Certificate{}, nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	return pair, caPEM, err
}

func loadOrCreateCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	certPEM, keyPEM, err := read(dir, "ca")
	if err == nil {
		cert, key, err := parse(certPEM, keyPEM)
		return cert, key, certPEM, err
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "blastgate local CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM, keyPEM, err = encode(der, key)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := write(dir, "ca", certPEM, keyPEM); err != nil {
		return nil, nil, nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key, certPEM, nil
}

func issue(ca *x509.Certificate, caKey *ecdsa.PrivateKey, hosts []string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "blastgate"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	return encode(der, key)
}

func usable(certPEM []byte, ca *x509.Certificate, hosts []string) bool {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil || time.Until(c.NotAfter) < renewBefore {
		return false
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	for _, h := range hosts {
		if _, err := c.Verify(x509.VerifyOptions{Roots: pool, DNSName: h}); err != nil {
			return false
		}
	}
	return true
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

func encode(der []byte, key *ecdsa.PrivateKey) ([]byte, []byte, error) {
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), nil
}

func parse(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, errors.New("unreadable PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	return cert, key, err
}

func read(dir, name string) ([]byte, []byte, error) {
	c, err := os.ReadFile(filepath.Join(dir, name+".crt"))
	if err != nil {
		return nil, nil, err
	}
	k, err := os.ReadFile(filepath.Join(dir, name+".key"))
	return c, k, err
}

func write(dir, name string, certPEM, keyPEM []byte) error {
	if err := os.WriteFile(filepath.Join(dir, name+".key"), keyPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".crt"), certPEM, 0o644)
}
