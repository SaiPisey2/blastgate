# blastgate

A gateway between AI agents and Kubernetes. Every action an agent takes goes through
blastgate, which forwards it as the human who owns the agent's session, so the
cluster's own RBAC and audit log see a person, an agent and a session — never a
shared admin credential.

Scoring what an action would destroy, and holding the risky ones for a person, is
the next stage. This build is the proxy it will sit in.

## License

Apache 2.0
