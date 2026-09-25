package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/SaiPisey2/blastgate/internal/config"
	"github.com/SaiPisey2/blastgate/internal/tlsutil"
)

// webhookConfigCmd prints the ValidatingWebhookConfiguration that points
// the cluster at blastgate's observe-only webhook. It prints rather than
// applies: registering a webhook for every write in the cluster is a
// change the operator should read and kubectl apply themselves.
func webhookConfigCmd(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	const usage = "usage: blastgate webhook-config --url https://<host>:<port>/validate"
	fs := flag.NewFlagSet("webhook-config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rawURL := fs.String("url", "", "the address the API server reaches the webhook at (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *rawURL == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	u, err := url.Parse(*rawURL)
	// The API server refuses a webhook URL that is not https or carries
	// user info or a fragment; catching it here beats a kubectl apply
	// error later. The handler only answers /validate, so any other path
	// (or a query it would ignore) would register a webhook that 404s on
	// every review and, under failurePolicy Ignore, records nothing.
	if err == nil && u.Path == "" && u.RawPath == "" {
		u.Path = "/validate"
	}
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Path != "/validate" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		fmt.Fprintf(stderr, "--url %q must be https://<host>[:<port>]/validate, without user info, query or fragment\n", *rawURL)
		return 2
	}
	// Rebuilt from the checked parts so nothing the checks did not look
	// at reaches the printed configuration.
	webhookURL := (&url.URL{Scheme: "https", Host: u.Host, Path: "/validate"}).String()
	cfg, err := config.LoadLocal(getenv)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// Without it the configuration would apply cleanly
	// and every review would then fail TLS verification; with
	// failurePolicy: Ignore that failure is silent, and the webhook
	// would observe nothing while looking installed.
	if !covered(u.Hostname(), cfg.TLSHosts) {
		fmt.Fprintf(stderr, "the serving certificate does not cover %q (BLASTGATE_TLS_HOSTS is %q), so the API server would fail to verify the webhook and, with failurePolicy Ignore, silently record nothing; add %[1]q to BLASTGATE_TLS_HOSTS and restart serve so the certificate is reissued\n",
			u.Hostname(), strings.Join(cfg.TLSHosts, ","))
		return 2
	}
	// Read-only: this command never creates the CA or (re)issues the
	// serving certificate. Doing so here would rewrite the pair under a
	// running serve, and a CA created by a command that only prints it is
	// one nobody meant to create. serve, or session new, creates it.
	caPEM, err := tlsutil.LoadCA(filepath.Join(cfg.DataDir, "tls"))
	if errors.Is(err, tlsutil.ErrNoCA) {
		fmt.Fprintf(stderr, "no certificate authority in %s yet; run `blastgate serve` once (it creates the CA and the serving certificate for BLASTGATE_TLS_HOSTS), then run webhook-config again\n",
			filepath.Join(cfg.DataDir, "tls"))
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	out, err := yaml.Marshal(observeConfig(webhookURL, caPEM))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// covered reports whether a certificate issued for hosts (as tlsutil
// issues it: IPs as IP SANs, everything else as DNS SANs) verifies for
// host. It asks crypto/x509 on a template rather than comparing strings,
// so "::1" matches "0:0:0:0:0:0:0:1" and case and wildcards follow the
// same rules the API server's TLS client will apply.
func covered(host string, hosts []string) bool {
	var c x509.Certificate
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			c.IPAddresses = append(c.IPAddresses, ip)
		} else {
			c.DNSNames = append(c.DNSNames, h)
		}
	}
	return c.VerifyHostname(host) == nil
}

// observeConfig is the registration. Every value that decides whether
// the webhook can hurt the cluster is pinned here: failurePolicy Ignore
// and the 5s timeout mean an unreachable or slow blastgate lets writes
// through, and sideEffects None lets dry-run requests reach it.
func observeConfig(url string, caPEM []byte) *admissionregistrationv1.ValidatingWebhookConfiguration {
	ignore := admissionregistrationv1.Ignore
	none := admissionregistrationv1.SideEffectClassNone
	equivalent := admissionregistrationv1.Equivalent
	scope := admissionregistrationv1.AllScopes
	timeout := int32(5)
	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		TypeMeta:   metav1.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingWebhookConfiguration"},
		ObjectMeta: metav1.ObjectMeta{Name: "blastgate-observe"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name:                    "observe.blastgate.local",
			ClientConfig:            admissionregistrationv1.WebhookClientConfig{URL: &url, CABundle: caPEM},
			FailurePolicy:           &ignore,
			SideEffects:             &none,
			TimeoutSeconds:          &timeout,
			AdmissionReviewVersions: []string{"v1"},
			MatchPolicy:             &equivalent,
			Rules: []admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{
					admissionregistrationv1.Create, admissionregistrationv1.Update,
					admissionregistrationv1.Delete, admissionregistrationv1.Connect,
				},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"*"},
					APIVersions: []string{"*"},
					Resources:   []string{"*/*"},
					Scope:       &scope,
				},
			}},
		}},
	}
}
