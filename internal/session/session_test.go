package session

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/tools/clientcmd"

	"github.com/SaiPisey2/blastgate/internal/store"
)

func TestValidate(t *testing.T) {
	ok := [][2]string{{"alice@corp.com", "coding-agent"}, {"bob", "a"}, {"ops-team", "agent-1"}}
	for _, c := range ok {
		if err := Validate(c[0], c[1]); err != nil {
			t.Errorf("Validate(%q, %q) = %v", c[0], c[1], err)
		}
	}
	bad := [][2]string{
		{"", "coding-agent"},
		{"system:admin", "coding-agent"},
		{"system:kube-controller-manager", "x"},
		{"alice smith", "x"},
		{"alice\r\nImpersonate-Group: system:masters", "x"},
		{"alice", ""},
		{"alice", "Agent"},
		{"alice", "has space"},
		{"alice", strings.Repeat("a", 64)},
		{"alice", "-leading"},
	}
	for _, c := range bad {
		if err := Validate(c[0], c[1]); err == nil {
			t.Errorf("Validate(%q, %q) accepted", c[0], c[1])
		}
	}
}

func TestNewMintsDistinctPrefixedTokens(t *testing.T) {
	now := time.Now()
	s1, t1, err := New("alice", "coding-agent", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	_, t2, _ := New("alice", "coding-agent", time.Hour, now)
	if t1 == t2 || !strings.HasPrefix(t1, TokenPrefix) || len(t1) < 40 {
		t.Errorf("tokens %q %q", t1, t2)
	}
	if !s1.Expires.Equal(now.Add(time.Hour)) || s1.ID == "" {
		t.Errorf("session %+v", s1)
	}
}

func TestNewRefusesBadTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Minute, MaxTTL + time.Second} {
		if _, _, err := New("alice", "x", ttl, time.Now()); err == nil {
			t.Errorf("ttl %v accepted", ttl)
		}
	}
}

type fakeLookup map[string]store.Session

func (f fakeLookup) SessionByTokenHash(_ context.Context, h []byte) (store.Session, error) {
	s, ok := f[string(h)]
	if !ok {
		return store.Session{}, store.ErrNotFound
	}
	return s, nil
}

func req(auth string) *http.Request {
	r, _ := http.NewRequest("GET", "https://x/api", nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	return r
}

func TestAuthenticate(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	live := store.Session{ID: "live", Human: "alice", Agent: "x", Expires: now.Add(time.Hour)}
	expired := store.Session{ID: "exp", Human: "alice", Agent: "x", Expires: now}
	revoked := store.Session{ID: "rev", Human: "alice", Agent: "x", Expires: now.Add(time.Hour), Revoked: now.Add(-time.Minute)}
	a := &Authenticator{
		Store: fakeLookup{string(Hash("bg_live")): live, string(Hash("bg_exp")): expired, string(Hash("bg_rev")): revoked},
		Now:   func() time.Time { return now },
	}
	if s, err := a.Authenticate(req("Bearer bg_live")); err != nil || s.ID != "live" {
		t.Errorf("live: %+v %v", s, err)
	}
	for name, h := range map[string]string{
		"missing":     "",
		"basic":       "Basic YWxpY2U6cHc=",
		"no-prefix":   "Bearer live",
		"unknown":     "Bearer bg_nope",
		"expired":     "Bearer bg_exp",
		"revoked":     "Bearer bg_rev",
		"lowercase":   "bearer bg_live",
		"extra-space": "Bearer  bg_live",
	} {
		if _, err := a.Authenticate(req(h)); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want ErrUnauthenticated", name, err)
		}
	}
}

func TestKubeconfigRoundTrips(t *testing.T) {
	s := store.Session{ID: "abc123", Human: "alice", Agent: "x"}
	b, err := Kubeconfig("https://127.0.0.1:8443", []byte("CA-PEM"), "bg_tok", "demo", s)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := clientcmd.Load(b)
	if err != nil {
		t.Fatal(err)
	}
	ctx := cfg.Contexts[cfg.CurrentContext]
	if ctx == nil || ctx.Namespace != "demo" {
		t.Fatalf("context = %+v", ctx)
	}
	if cfg.Clusters[ctx.Cluster].Server != "https://127.0.0.1:8443" || string(cfg.Clusters[ctx.Cluster].CertificateAuthorityData) != "CA-PEM" {
		t.Errorf("cluster = %+v", cfg.Clusters[ctx.Cluster])
	}
	if cfg.AuthInfos[ctx.AuthInfo].Token != "bg_tok" {
		t.Errorf("token not carried")
	}
}
