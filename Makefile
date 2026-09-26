.PHONY: build test ui ui-test

build:
	CGO_ENABLED=0 go build -o blastgate ./cmd/blastgate

test:
	go test -race -count=1 ./...

# The UI is built into ui/dist, which is committed and embedded, so `build`
# needs no Node. Run `make ui` after changing ui/src and commit ui/dist.
ui:
	cd ui && npm ci && npm run build

ui-test:
	cd ui && npm ci && npm test -- --run

# The fixture is its own kind cluster with its own kubeconfig files under
# fixture/. Every command names those files explicitly; nothing here falls
# back to KUBECONFIG or ~/.kube/config.
CLUSTER  := blastgate-fixture
ADMIN_KC := $(CURDIR)/fixture/admin.kubeconfig
UP_KC    := $(CURDIR)/fixture/upstream.kubeconfig
KC       := kubectl --kubeconfig $(ADMIN_KC)

.PHONY: fixture-up fixture-test fixture-down

# umask 077 and chmod: the admin kubeconfig is cluster-admin on the
# fixture, and a redirect into an existing file keeps that file's mode.
fixture-up:
	@umask 077; if ! kind get clusters | grep -qx '$(CLUSTER)'; then \
		kind create cluster --name $(CLUSTER) --config fixture/kind.yaml --kubeconfig $(ADMIN_KC); \
	else \
		kind get kubeconfig --name $(CLUSTER) > $(ADMIN_KC); \
	fi; chmod 600 $(ADMIN_KC)
	$(KC) wait --for=condition=Ready node --all --timeout=120s
	$(KC) apply -f fixture/manifests/
	$(KC) -n demo rollout status deploy/web --timeout=180s
	$(KC) -n demo rollout status deploy/db --timeout=180s
	$(KC) -n demo wait --for=jsonpath='{.status.phase}'=Bound pvc/data --timeout=120s
	sh fixture/mkupstream.sh $(ADMIN_KC) $(UP_KC)

# The suite deletes the demo claim and changes the demo workloads, so a
# second run needs a fresh fixture: make fixture-down; make fixture-up.
#
# BLASTGATE_E2E_HOST_IP is the kind network's gateway: the host as the
# node sees it, where the webhook tests run blastgate's webhook listener
# for the API server to call. Read here rather than in fixture-up, since
# make runs each target in its own shell and nothing exported survives.
fixture-test: build
	cd e2e && BLASTGATE_E2E_ADMIN=$(ADMIN_KC) BLASTGATE_E2E_UPSTREAM=$(UP_KC) \
		BLASTGATE_E2E_HOST_IP=$$(docker network inspect kind -f '{{(index .IPAM.Config 0).Gateway}}') \
		go test -tags=e2e -count=1 -v .

fixture-down:
	# --kubeconfig: without it kind removes the context from the default
	# kubeconfig, which means opening, locking and rewriting that file.
	kind delete cluster --name $(CLUSTER) --kubeconfig $(ADMIN_KC)
	rm -f $(ADMIN_KC) $(UP_KC)
