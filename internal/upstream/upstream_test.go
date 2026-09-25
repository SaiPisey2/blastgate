package upstream

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/client-go/rest"

	"github.com/SaiPisey2/blastgate/internal/config"
)

func tlsServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *rest.Config) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return srv, &rest.Config{Host: srv.URL, BearerToken: "sa-token", TLSClientConfig: rest.TLSClientConfig{CAData: ca}}
}

// HTTP/2 has no protocol upgrade. exec, attach and port-forward over the
// normal transport would negotiate h2 with any modern API server and fail.
func TestUpgradeTransportSpeaksHTTP1(t *testing.T) {
	var protos []int
	var auths []string
	srv, cfg := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		protos = append(protos, r.ProtoMajor)
		auths = append(auths, r.Header.Get("Authorization"))
	})
	up, err := FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, rt := range []http.RoundTripper{up.Normal, up.Upgrade} {
		req, _ := http.NewRequest("GET", srv.URL+"/api", nil)
		res, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}
	if protos[0] != 2 {
		t.Errorf("normal transport used HTTP/%d, want 2 (the test server offers h2)", protos[0])
	}
	if protos[1] != 1 {
		t.Errorf("upgrade transport used HTTP/%d, want 1", protos[1])
	}
	for i, a := range auths {
		if a != "Bearer sa-token" {
			t.Errorf("request %d authorization = %q, want the service-account token", i, a)
		}
	}
}

func TestRefusesAnUpstreamThatAlreadyImpersonates(t *testing.T) {
	_, cfg := tlsServer(t, func(http.ResponseWriter, *http.Request) {})
	cfg.Impersonate.UserName = "someone"
	if _, err := FromConfig(cfg); err == nil || !strings.Contains(err.Error(), "impersonat") {
		t.Errorf("err = %v", err)
	}
}

func TestRefusesPlainHTTP(t *testing.T) {
	if _, err := FromConfig(&rest.Config{Host: "http://127.0.0.1:6443", BearerToken: "x"}); err == nil {
		t.Error("plain http accepted; the service-account token would travel in the clear")
	}
}

func TestLoadRequiresAnExplicitPath(t *testing.T) {
	// A missing file must fail, not fall back to any default kubeconfig.
	if _, err := Load(configWithPath("/nonexistent/upstream.kubeconfig")); err == nil {
		t.Error("a missing upstream kubeconfig was accepted")
	}
}

func configWithPath(p string) config.Config { return config.Config{UpstreamKubeconfig: p} }

// Scoring one delete makes a few dozen reads through sounding. Under
// client-go's default limiter (5 per second after a burst of 10) that
// took 4.4s on an idle kind cluster -- most of the 5s score budget -- and
// on a larger cluster would run past it, holding every delete as
// unmeasured. Found live.
func TestScoringConfigIsNotThrottledLikeADefaultClient(t *testing.T) {
	_, cfg := tlsServer(t, func(http.ResponseWriter, *http.Request) {})
	up, err := FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if up.Config.QPS < 100 || up.Config.Burst < 200 {
		t.Errorf("scoring config QPS %v burst %d", up.Config.QPS, up.Config.Burst)
	}
	if cfg.QPS != 0 || cfg.Burst != 0 {
		t.Errorf("the caller's config was changed: QPS %v burst %d", cfg.QPS, cfg.Burst)
	}
}
