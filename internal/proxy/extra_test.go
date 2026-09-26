package proxy

import (
	"strings"
	"testing"

	"github.com/SaiPisey2/blastgate/internal/webhook"
)

// TestSessionHeaderIsTheWebhooksExtra: the proxy impersonates with
// HeaderSession, the API server turns Impersonate-Extra-<key> into the
// lowercased user extra <key>, and the webhook treats a write carrying
// webhook.SessionExtra as one that came through blastgate. If the two
// names drift apart, every write through blastgate is recorded as a
// bypass and nothing fails to say so.
func TestSessionHeaderIsTheWebhooksExtra(t *testing.T) {
	const prefix = "Impersonate-Extra-"
	if !strings.HasPrefix(HeaderSession, prefix) {
		t.Fatalf("HeaderSession %q is not an impersonated extra", HeaderSession)
	}
	if got := strings.ToLower(strings.TrimPrefix(HeaderSession, prefix)); got != webhook.SessionExtra {
		t.Errorf("the proxy sets extra %q, the webhook looks for %q", got, webhook.SessionExtra)
	}
}
