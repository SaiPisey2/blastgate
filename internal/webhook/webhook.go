// Package webhook is an observe-only validating admission webhook. It
// answers every AdmissionReview with allowed: true and records the writes
// that reached the cluster without passing through blastgate, so an
// operator can see a kubeconfig that goes around the gateway. It never
// denies: a bug or outage here must not be able to break the cluster.
package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/SaiPisey2/blastgate/internal/store"
)

// SessionExtra is the user-info extra the proxy impersonates with
// (Impersonate-Extra-Blastgate-Session). The API server lowercases extra
// keys, and passes them to admission unchanged.
const SessionExtra = "blastgate-session"

// maxBody bounds one AdmissionReview. The API server caps a request
// object at 3 MiB (etcd's limit sits just above), so anything larger is
// not a review it sent, and reading it unbounded would let a flood of
// huge bodies exhaust memory.
const maxBody = 3 << 20

// recordTimeout bounds the synchronous write of one bypass row, well
// inside the configuration's timeoutSeconds: 5, so a slow disk turns into
// a missed row and a log line, never an API server timeout.
const recordTimeout = 2 * time.Second

// DefaultIgnore are the username prefixes of Kubernetes' own components.
// Without them every ReplicaSet scaling, garbage collection and kubelet
// status update would be a bypass record and drown the ones that matter.
// kube-system service accounts are the controllers
// (system:serviceaccount:kube-system:replicaset-controller); a service
// account in any other namespace is someone's workload, possibly an agent
// holding a token, and is recorded.
var DefaultIgnore = []string{"system:node:", "system:kube-", "system:serviceaccount:kube-system:", "system:apiserver"}

// Recorder is the part of the store the webhook writes to.
type Recorder interface {
	AppendBypass(ctx context.Context, b store.BypassRow) error
}

// Handler serves POST /validate. Log and Now may be nil.
type Handler struct {
	Rec    Recorder
	Ignore []string
	Log    *slog.Logger
	Now    func() time.Time
}

// ViaBlastgate reports whether the request carried a blastgate session.
// An empty value does not count: it is what a hand-written impersonation
// header with nothing in it produces, not a session the proxy set.
func ViaBlastgate(extra map[string]authenticationv1.ExtraValue) bool {
	for _, v := range extra[SessionExtra] {
		if v != "" {
			return true
		}
	}
	return false
}

// Ignored reports whether user starts with one of prefixes.
func Ignored(user string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(user, p) {
			return true
		}
	}
	return false
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/validate" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "admission review too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "reading body", http.StatusBadRequest)
		return
	}

	var ar admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &ar); err != nil || ar.Request == nil {
		// A review whose typed decode fails (a field this client version
		// reads differently) still gets allowed when its uid is readable:
		// the answer is allowed either way, and a 400 would only put an
		// error in the API server's log. Nothing is recorded, because
		// nothing about the request can be trusted to be what it says.
		var probe struct {
			Request struct {
				UID string `json:"uid"`
			} `json:"request"`
		}
		if json.Unmarshal(body, &probe) != nil || probe.Request.UID == "" {
			// failurePolicy: Ignore turns this into an allowed request.
			http.Error(w, "not an AdmissionReview", http.StatusBadRequest)
			return
		}
		h.allow(w, types.UID(probe.Request.UID))
		return
	}
	req := ar.Request
	if h.bypassed(req) {
		h.record(r.Context(), req)
	}
	h.allow(w, req.UID)
}

// bypassed is whether req is a write that did not come through blastgate
// and was not made by the control plane itself.
func (h *Handler) bypassed(req *admissionv1.AdmissionRequest) bool {
	switch req.Operation {
	case admissionv1.Create, admissionv1.Update, admissionv1.Delete, admissionv1.Connect:
	default:
		return false
	}
	return !ViaBlastgate(req.UserInfo.Extra) && !Ignored(req.UserInfo.Username, h.Ignore)
}

func (h *Handler) record(ctx context.Context, req *admissionv1.AdmissionRequest) {
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	row := store.BypassRow{
		At:     now(),
		User:   req.UserInfo.Username,
		Groups: req.UserInfo.Groups,
		// Lowercased to read like the audit trail's verbs; an admission
		// UPDATE covers both update and patch, which the API server does
		// not distinguish here.
		Verb:        strings.ToLower(string(req.Operation)),
		Group:       req.Resource.Group,
		Resource:    req.Resource.Resource,
		Subresource: req.SubResource,
		Namespace:   req.Namespace,
		Name:        req.Name,
		// The review's uid: a fresh UUID per review (not the object's
		// uid, which a CREATE does not have yet), so two rows for the
		// same object stay distinguishable.
		UID:    string(req.UID),
		DryRun: req.DryRun != nil && *req.DryRun,
	}
	// Detached from the request so the API server hanging up after its
	// own timeout does not throw away a row that was nearly written, but
	// still bounded so a stuck store cannot pile up goroutines.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	if err := h.Rec.AppendBypass(ctx, row); err != nil {
		h.logger().Error("recording bypass", "err", err, "user", row.User, "verb", row.Verb,
			"resource", row.Resource, "namespace", row.Namespace, "name", row.Name, "uid", row.UID)
	}
}

func (h *Handler) allow(w http.ResponseWriter, uid types.UID) {
	resp := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Response: &admissionv1.AdmissionResponse{UID: uid, Allowed: true},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger().Warn("writing admission response", "err", err)
	}
}

func (h *Handler) logger() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}
