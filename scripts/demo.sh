#!/usr/bin/env bash
# demo.sh runs blastgate against the kind fixture and plays one agent's
# afternoon: a read, an allowed change, three writes that are held (a
# delete that destroys a volume's data, a scale to zero of a prod
# Service's only backend, an exec running SQL) and one write made around
# blastgate with the admin kubeconfig, which the observe webhook records.
# It then keeps serving so the Waiting, Activity, Policy and Changes
# outside blastgate pages can be looked at in the web UI. Ctrl-C stops blastgate and removes the
# webhook registration.
#
#   make fixture-up && make build && scripts/demo.sh
#
# It only ever talks to the fixture: every kubectl names a kubeconfig
# under fixture/ (or the paths given in BLASTGATE_DEMO_ADMIN_KC and
# BLASTGATE_DEMO_UPSTREAM_KC), and KUBECONFIG is pointed at nothing so a
# forgotten --kubeconfig fails instead of reaching the default cluster.
set -euo pipefail
export KUBECONFIG=/nonexistent

root=$(cd "$(dirname "$0")/.." && pwd)
admin_kc=${BLASTGATE_DEMO_ADMIN_KC:-$root/fixture/admin.kubeconfig}
up_kc=${BLASTGATE_DEMO_UPSTREAM_KC:-$root/fixture/upstream.kubeconfig}
bin=${BLASTGATE_BIN:-$root/blastgate}
node=blastgate-fixture-control-plane
webhook_port=${BLASTGATE_DEMO_WEBHOOK_PORT:-8445}

die() { echo "demo: $*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

for f in "$admin_kc" "$up_kc"; do
  [ -f "$f" ] || die "no kubeconfig at $f; run make fixture-up first (the default kubeconfig is never used)"
done
[ -x "$bin" ] || die "no blastgate binary at $bin; run make build first"

# The same guard as the e2e suite: the admin kubeconfig must be the
# fixture's, and the upstream (the one blastgate forwards with) must point
# at the same API server.
ctx=$(kubectl --kubeconfig "$admin_kc" config current-context)
[ "$ctx" = kind-blastgate-fixture ] || die "refusing: $admin_kc has context $ctx, not kind-blastgate-fixture"
server() { kubectl --kubeconfig "$1" config view --minify -o jsonpath='{.clusters[0].cluster.server}'; }
[ "$(server "$admin_kc")" = "$(server "$up_kc")" ] || die "refusing: $up_kc does not point at the fixture's API server"

admin() { kubectl --kubeconfig "$admin_kc" "$@"; }

work=$(mktemp -d)
chmod 700 "$work"
serve_pid=
registered=
cleanup() {
  if [ -n "$registered" ]; then
    admin delete validatingwebhookconfiguration blastgate-observe --ignore-not-found >/dev/null || true
  fi
  # So the demo can run again on the same fixture: every other write it
  # makes is held, or (the annotation) repeatable.
  admin delete configmap hotfix -n demo --ignore-not-found >/dev/null || true
  if [ -n "$serve_pid" ]; then
    kill -INT "$serve_pid" 2>/dev/null || true
    wait "$serve_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

export BLASTGATE_DATA_DIR=$work/data
BLASTGATE_SIGNING_KEY=$(openssl rand -hex 32)
export BLASTGATE_SIGNING_KEY
export BLASTGATE_UPSTREAM_KUBECONFIG=$up_kc
export BLASTGATE_LISTEN=${BLASTGATE_LISTEN:-127.0.0.1:8443}
export BLASTGATE_ADMIN_LISTEN=${BLASTGATE_ADMIN_LISTEN:-127.0.0.1:8444}
# A short hold, so each held command prints its ticket after 3s instead of 45s.
export BLASTGATE_HOLD=3s

# Where the kind API server can reach the webhook, in the e2e suite's
# order: the kind network's gateway where the host really has that
# address (Linux), else Docker Desktop's host.docker.internal, which it
# forwards to this machine's loopback. Never a LAN address.
gw=$(docker network inspect kind -f '{{(index .IPAM.Config 0).Gateway}}')
if { ifconfig 2>/dev/null || ip -o addr show 2>/dev/null; } | grep -qFw "inet $gw"; then
  webhook_host=$gw
  export BLASTGATE_WEBHOOK_LISTEN=$gw:$webhook_port
  # The gateway is not loopback, so binding it is opt-in; it faces only
  # the kind bridge.
  export BLASTGATE_ALLOW_REMOTE=1
elif docker exec "$node" getent hosts host.docker.internal >/dev/null 2>&1; then
  webhook_host=host.docker.internal
  export BLASTGATE_WEBHOOK_LISTEN=127.0.0.1:$webhook_port
else
  die "the kind node cannot reach this host at $gw or host.docker.internal"
fi
export BLASTGATE_TLS_HOSTS=127.0.0.1,localhost,$webhook_host
webhook_url=https://$webhook_host:$webhook_port/validate

step "blastgate serve (data in $work)"
"$bin" serve 2>"$work/serve.log" &
serve_pid=$!
for _ in $(seq 50); do
  curl -sk --noproxy '*' -o /dev/null "https://$BLASTGATE_ADMIN_LISTEN/" && break
  kill -0 "$serve_pid" 2>/dev/null || { cat "$work/serve.log" >&2; die "serve exited"; }
  sleep 0.2
done
echo "proxy https://$BLASTGATE_LISTEN, admin UI https://$BLASTGATE_ADMIN_LISTEN, webhook $BLASTGATE_WEBHOOK_LISTEN"

step "register the observe webhook as $webhook_url"
code=$(docker exec "$node" curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$webhook_url" || true)
[ "$code" = 405 ] || die "the kind node cannot reach $webhook_url (got $code)"
"$bin" webhook-config --url "$webhook_url" | admin apply -f -
registered=1

step "an approver, bob, and a session for alice's coding-agent"
(umask 077; "$bin" approver new --name bob >"$work/bob.token")
(umask 077; "$bin" session new --human alice --agent coding-agent --ttl 1h --namespace demo >"$work/agent.kubeconfig")

agent() { kubectl --kubeconfig "$work/agent.kubeconfig" --cache-dir "$work/cache" "$@"; }
# held runs an agent command that the default policy holds: kubectl exits
# non-zero with the ticket, which is the point, so it must not stop the script.
held() {
  echo "\$ kubectl $(printf '%q ' "$@")"
  if agent "$@" 2>&1; then echo "(went through: not held)"; fi
}

step "the agent reads, and makes a change the policy allows"
agent get pods -n demo
agent annotate deployment web -n demo demo/owner=alice --overwrite

step "the agent deletes the claim holding the database's data: held"
held delete pvc data -n demo --wait=false

step "the agent scales the only backend of a prod Service to zero: held"
held scale deployment web -n demo --replicas=0

step "the agent runs SQL in the database pod: held"
held exec -n demo deploy/db -- psql -c 'drop table orders'

step "someone writes with the admin kubeconfig, around blastgate: recorded as a change outside blastgate"
admin create configmap hotfix -n demo --from-literal=reason=manual

cat <<EOF

Open https://$BLASTGATE_ADMIN_LISTEN and sign in with the token in
  $work/bob.token
The certificate is signed by blastgate's own CA, $work/data/tls/ca.crt.
Waiting holds the three requests; Activity's banner opens Changes outside
blastgate, which lists the configmap.
Ctrl-C stops blastgate, removes the webhook registration and deletes $work.
EOF
wait "$serve_pid"
