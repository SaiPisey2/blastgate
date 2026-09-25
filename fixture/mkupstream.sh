#!/bin/sh
# Writes the kubeconfig blastgate forwards with: the blastgate service
# account's token against the fixture cluster. Every kubectl call names the
# fixture's admin kubeconfig explicitly -- nothing here reads KUBECONFIG or
# ~/.kube/config, which on a workstation may be a real cluster.
set -eu
ADMIN="$1"
OUT="$2"
ctx=$(kubectl --kubeconfig "$ADMIN" config current-context)
if [ "$ctx" != "kind-blastgate-fixture" ]; then
  echo "refusing: $ADMIN has context $ctx, not kind-blastgate-fixture" >&2
  exit 1
fi
server=$(kubectl --kubeconfig "$ADMIN" config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')
ca=$(kubectl --kubeconfig "$ADMIN" config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
token=$(kubectl --kubeconfig "$ADMIN" -n blastgate-system create token blastgate --duration=24h)
umask 077
cat > "$OUT" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: fixture
  cluster:
    server: $server
    certificate-authority-data: $ca
users:
- name: blastgate
  user:
    token: $token
contexts:
- name: fixture
  context:
    cluster: fixture
    user: blastgate
current-context: fixture
EOF
