.PHONY: build test

build:
	CGO_ENABLED=0 go build -o blastgate ./cmd/blastgate

test:
	go test -race -count=1 ./...

# The fixture is its own kind cluster with its own kubeconfig files under
# fixture/. Every command names those files explicitly; nothing here falls
# back to KUBECONFIG or ~/.kube/config.
CLUSTER  := blastgate-fixture
ADMIN_KC := $(CURDIR)/fixture/admin.kubeconfig
UP_KC    := $(CURDIR)/fixture/upstream.kubeconfig
KC       := kubectl --kubeconfig $(ADMIN_KC)

.PHONY: fixture-up fixture-test fixture-down

fixture-up:
	@if ! kind get clusters | grep -qx '$(CLUSTER)'; then \
		kind create cluster --name $(CLUSTER) --config fixture/kind.yaml --kubeconfig $(ADMIN_KC); \
	else \
		kind get kubeconfig --name $(CLUSTER) > $(ADMIN_KC); \
	fi
	$(KC) wait --for=condition=Ready node --all --timeout=120s
	$(KC) apply -f fixture/manifests/
	$(KC) -n demo rollout status deploy/web --timeout=180s
	sh fixture/mkupstream.sh $(ADMIN_KC) $(UP_KC)

fixture-test: build
	cd e2e && BLASTGATE_E2E_ADMIN=$(ADMIN_KC) BLASTGATE_E2E_UPSTREAM=$(UP_KC) go test -tags=e2e -count=1 -v .

fixture-down:
	# --kubeconfig: without it kind removes the context from the default
	# kubeconfig, which means opening, locking and rewriting that file.
	kind delete cluster --name $(CLUSTER) --kubeconfig $(ADMIN_KC)
	rm -f $(ADMIN_KC) $(UP_KC)
