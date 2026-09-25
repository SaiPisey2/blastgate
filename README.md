# blastgate

A gateway between AI agents and Kubernetes. An agent's kubectl talks to blastgate,
and blastgate forwards each request **as the human who owns the agent's session**,
using Kubernetes impersonation — so the cluster's own RBAC decides what the agent
may do, and the cluster's own audit log records a person, an agent and a session
instead of a shared admin credential.

Scoring what an action would destroy, and holding the risky ones for a person,
comes next. This build is the proxy that work plugs into.

## Try it

```sh
export BLASTGATE_DATA_DIR=~/.blastgate
export BLASTGATE_SIGNING_KEY=$(openssl rand -hex 32)
export BLASTGATE_UPSTREAM_KUBECONFIG=./blastgate-sa.kubeconfig   # see below
blastgate serve &
blastgate session new --human alice@example.com --agent coding-agent --ttl 8h > agent.kubeconfig
KUBECONFIG=agent.kubeconfig kubectl get pods
```

The upstream kubeconfig is blastgate's own service account, which needs **only**
`impersonate` on `users` and on `userextras/blastgate-agent` and
`userextras/blastgate-session` — see `fixture/manifests/01-blastgate.yaml`.
blastgate never reads your default kubeconfig.

## What it guarantees

- Every request is sent as the session's human. The agent's token is never forwarded.
- A request carrying its own `Impersonate-*` or `X-Remote-*` header — or declaring one
  as a trailer — is refused.
- Sessions for `system:` users are refused.
- It will not start without a signing key, without an explicitly named upstream, or
  on a non-loopback address unless told to.
- Tokens are stored only as hashes; logs never contain a token, a body or a query string.
- A refusal (client impersonation, a bad or revoked session, an upstream error) is also
  sent as a `Warning: 299` header, since kubectl does not print a `Status` body on the
  discovery requests it makes before your command.
- Every request is logged once, including one a client aborts mid-stream — logged as
  aborted, with the outcome recorded as unknown rather than guessed.

## What it does not do yet

- Score or hold anything — every authenticated request is forwarded.
- Carry the human's groups: impersonation here sets the user only, so RBAC must bind
  the user name.
- Stop an agent that holds other credentials to the cluster.

## Verified

`make fixture-up fixture-test` runs the real kubectl through blastgate against a kind
cluster: get, watch, server-side apply, delete, logs and `logs -f`, exec with stdin
over WebSocket and SPDY, and port-forward over both. On a list call against that
cluster: direct p50 861µs, p95 1.530ms; through blastgate p50 1.455ms, p95 1.993ms.
Added latency: p50 **594µs**, p95 **463µs**.

## License

Apache 2.0
