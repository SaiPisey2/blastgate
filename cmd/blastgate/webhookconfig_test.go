package main

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/yaml"
)

func TestWebhookConfigPinsFailurePolicyIgnore(t *testing.T) {
	dir := t.TempDir()
	env := func(k string) string {
		return map[string]string{"BLASTGATE_DATA_DIR": dir, "BLASTGATE_TLS_HOSTS": "127.0.0.1,gate.internal"}[k]
	}
	code, out, errs := runCLI(env, "webhook-config", "--url", "https://gate.internal:8445/validate")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var cfg admissionregistrationv1.ValidatingWebhookConfiguration
	if err := yaml.UnmarshalStrict([]byte(out), &cfg); err != nil {
		t.Fatalf("output is not a ValidatingWebhookConfiguration: %v\n%s", err, out)
	}
	if cfg.APIVersion != "admissionregistration.k8s.io/v1" || cfg.Kind != "ValidatingWebhookConfiguration" || cfg.Name != "blastgate-observe" {
		t.Errorf("header = %s %s %s", cfg.APIVersion, cfg.Kind, cfg.Name)
	}
	if len(cfg.Webhooks) != 1 {
		t.Fatalf("webhooks = %d, want 1", len(cfg.Webhooks))
	}
	w := cfg.Webhooks[0]
	if w.FailurePolicy == nil || *w.FailurePolicy != admissionregistrationv1.Ignore {
		t.Errorf("failurePolicy = %v, want Ignore", w.FailurePolicy)
	}
	if w.SideEffects == nil || *w.SideEffects != admissionregistrationv1.SideEffectClassNone {
		t.Errorf("sideEffects = %v, want None", w.SideEffects)
	}
	if w.TimeoutSeconds == nil || *w.TimeoutSeconds != 5 {
		t.Errorf("timeoutSeconds = %v, want 5", w.TimeoutSeconds)
	}
	if w.MatchPolicy == nil || *w.MatchPolicy != admissionregistrationv1.Equivalent {
		t.Errorf("matchPolicy = %v, want Equivalent", w.MatchPolicy)
	}
	if strings.Join(w.AdmissionReviewVersions, ",") != "v1" {
		t.Errorf("admissionReviewVersions = %v", w.AdmissionReviewVersions)
	}
	if w.ClientConfig.URL == nil || *w.ClientConfig.URL != "https://gate.internal:8445/validate" || w.ClientConfig.Service != nil {
		t.Errorf("clientConfig = %+v", w.ClientConfig)
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, "tls", "ca.crt"))
	if err != nil {
		t.Fatalf("CA not written where serve reads it: %v", err)
	}
	if !bytes.Equal(w.ClientConfig.CABundle, caPEM) {
		t.Errorf("caBundle is not the local CA")
	}
	if b, _ := pem.Decode(w.ClientConfig.CABundle); b == nil || b.Type != "CERTIFICATE" {
		t.Errorf("caBundle is not a PEM certificate")
	}
	if len(w.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(w.Rules))
	}
	r := w.Rules[0]
	var ops []string
	for _, o := range r.Operations {
		ops = append(ops, string(o))
	}
	if strings.Join(ops, ",") != "CREATE,UPDATE,DELETE,CONNECT" ||
		strings.Join(r.APIGroups, ",") != "*" || strings.Join(r.APIVersions, ",") != "*" ||
		strings.Join(r.Resources, ",") != "*/*" || r.Scope == nil || *r.Scope != admissionregistrationv1.AllScopes {
		t.Errorf("rule = %+v", r)
	}
}

func TestWebhookConfigRefusesAnUncoveredHost(t *testing.T) {
	dir := t.TempDir()
	env := func(k string) string { return map[string]string{"BLASTGATE_DATA_DIR": dir}[k] }
	code, out, errs := runCLI(env, "webhook-config", "--url", "https://gate.internal:8445/validate")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if out != "" {
		t.Errorf("printed a configuration anyway: %s", out)
	}
	if !strings.Contains(errs, "gate.internal") || !strings.Contains(errs, "BLASTGATE_TLS_HOSTS") {
		t.Errorf("refusal must name the host and the setting: %q", errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls")); !os.IsNotExist(err) {
		t.Errorf("a refused run created TLS files: %v", err)
	}
}

func TestWebhookConfigRefusals(t *testing.T) {
	env := tempEnv(t)
	for name, args := range map[string][]string{
		"no url":     {"webhook-config"},
		"plain http": {"webhook-config", "--url", "http://127.0.0.1:8445/validate"},
		"no host":    {"webhook-config", "--url", "https:///validate"},
		"stray arg":  {"webhook-config", "--url", "https://127.0.0.1:8445/validate", "extra"},
		"userinfo":   {"webhook-config", "--url", "https://u:p@127.0.0.1:8445/validate"},
	} {
		if code, out, _ := runCLI(env, args...); code != 2 || out != "" {
			t.Errorf("%s: exit %d, out %q; want 2 and nothing printed", name, code, out)
		}
	}
	// A covered IP, written differently, is still the same address.
	if code, _, errs := runCLI(env, "webhook-config", "--url", "https://127.0.0.1:8445/validate"); code != 0 {
		t.Errorf("loopback default refused: %s", errs)
	}
}
