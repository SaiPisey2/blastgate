// Package session is who an agent is acting for. A session binds one human
// and one agent name to a random bearer token, for a bounded time; blastgate
// stores only the token's hash, and every forwarded request impersonates
// the session's human, so the cluster's RBAC and audit log see a person.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/SaiPisey2/blastgate/internal/store"
)

var ErrUnauthenticated = errors.New("unauthenticated")

const (
	TokenPrefix = "bg_"
	MaxTTL      = 7 * 24 * time.Hour
)

var agentName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Validate refuses names that would change what impersonation means.
//
// "system:" users are Kubernetes' own components -- several are bound to
// cluster-wide roles by user name alone, so impersonating one grants those
// roles. The human becomes an HTTP header value, so anything outside
// printable ASCII (a CR/LF above all) could smuggle a second header in.
// The agent name becomes an impersonation extra, and is kept to a DNS label.
func Validate(human, agent string) error {
	if human == "" {
		return errors.New("a human is required")
	}
	if len(human) > 253 {
		return errors.New("human name longer than 253 bytes")
	}
	if strings.HasPrefix(human, "system:") {
		return fmt.Errorf("refusing to act as %q: system: users are Kubernetes components, several bound to cluster-wide roles by name", human)
	}
	for i := 0; i < len(human); i++ {
		if c := human[i]; c < 0x21 || c > 0x7e {
			return fmt.Errorf("human name %q may contain only printable ASCII without spaces", human)
		}
	}
	if !agentName.MatchString(agent) {
		return fmt.Errorf("agent name %q must be lowercase letters, digits and dashes, at most 63", agent)
	}
	return nil
}

func New(human, agent string, ttl time.Duration, now time.Time) (store.Session, string, error) {
	if err := Validate(human, agent); err != nil {
		return store.Session{}, "", err
	}
	if ttl <= 0 || ttl > MaxTTL {
		return store.Session{}, "", fmt.Errorf("ttl %v must be positive and at most %v", ttl, MaxTTL)
	}
	id := make([]byte, 8)
	secret := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return store.Session{}, "", err
	}
	if _, err := rand.Read(secret); err != nil {
		return store.Session{}, "", err
	}
	s := store.Session{ID: hex.EncodeToString(id), Human: human, Agent: agent, Created: now, Expires: now.Add(ttl)}
	return s, TokenPrefix + base64.RawURLEncoding.EncodeToString(secret), nil
}

func Hash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

type Lookup interface {
	SessionByTokenHash(context.Context, []byte) (store.Session, error)
}

type Authenticator struct {
	Store Lookup
	Now   func() time.Time
}

// Authenticate returns the live session a request's bearer token names.
// Every way of failing -- no header, a malformed one, an unknown, expired
// or revoked token -- is the same ErrUnauthenticated, so the response says
// nothing about which tokens exist. A store failure is returned as itself:
// that is blastgate failing, not the caller.
func (a *Authenticator) Authenticate(r *http.Request) (store.Session, error) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || !strings.HasPrefix(tok, TokenPrefix) {
		return store.Session{}, ErrUnauthenticated
	}
	s, err := a.Store.SessionByTokenHash(r.Context(), Hash(tok))
	if errors.Is(err, store.ErrNotFound) {
		return store.Session{}, ErrUnauthenticated
	}
	if err != nil {
		return store.Session{}, err
	}
	if !s.Revoked.IsZero() || !a.Now().Before(s.Expires) {
		return store.Session{}, ErrUnauthenticated
	}
	return s, nil
}

func Kubeconfig(server string, caPEM []byte, token, namespace string, s store.Session) ([]byte, error) {
	name := "blastgate-" + s.ID
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters[name] = &clientcmdapi.Cluster{Server: server, CertificateAuthorityData: caPEM}
	cfg.AuthInfos[name] = &clientcmdapi.AuthInfo{Token: token}
	cfg.Contexts[name] = &clientcmdapi.Context{Cluster: name, AuthInfo: name, Namespace: namespace}
	cfg.CurrentContext = name
	return clientcmd.Write(*cfg)
}
