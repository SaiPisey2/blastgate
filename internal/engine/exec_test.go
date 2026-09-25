package engine

import (
	"context"
	"net/http"
	"testing"

	"github.com/SaiPisey2/blastgate/internal/normalize"
)

func TestDetectSQL(t *testing.T) {
	yes := [][]string{
		{"psql", "-c", "DROP TABLE users"},
		{"mysql", "-e", "select 1"},
		{"sh", "-c", "psql -U app -c 'delete from orders'"},
		{"mongosh", "--eval", "db.users.drop()"},
		{"redis-cli", "FLUSHALL"},
		{"sqlite3", "/data/app.db", "DELETE FROM t"},
	}
	no := [][]string{
		{"ls", "-la"},
		{"cat", "/etc/hosts"},
		{"sh", "-c", "echo selected items"},
		{"env"},
	}
	for _, c := range yes {
		if !detectSQL(c) {
			t.Errorf("missed %q", c)
		}
	}
	for _, c := range no {
		if detectSQL(c) {
			t.Errorf("false positive %q", c)
		}
	}
}

func TestExecIsUnmeasuredWithSQLFlag(t *testing.T) {
	a := normalize.Action{Verb: "create", Resource: "pods", Subresource: "exec", Query: map[string][]string{"command": {"psql", "-c", "drop table x"}}}
	i := assessExec(a)
	if i.Measured || i.Class != ClassTerminal || !i.SQLDetected {
		t.Errorf("impact = %+v", i)
	}
	a.Subresource = "portforward"
	a.Query = nil
	if i := assessExec(a); i.Measured || i.SQLDetected {
		t.Errorf("port-forward impact = %+v", i)
	}
}

func TestDetectSQLThroughShellPunctuation(t *testing.T) {
	for _, c := range [][]string{
		{"sh", "-c", "echo 'drop table x' | psql"},
		{"sh", "-c", "out=$(mysql -e 'show tables')"},
		{"/usr/bin/psql", "-l"},
		{"PSQL", "-l"},
		{"sh", "-c", "MySQL -e 'show tables'"},
	} {
		if !detectSQL(c) {
			t.Errorf("missed %q", c)
		}
	}
}

// Final review I3: `kubectl debug` adds an ephemeral container with a
// patch to pods/<x>/ephemeralcontainers. Measured as a mutation, the
// dry-run saw a REVERSIBLE change and the safe rule let an arbitrary
// command run unheld. Whatever the body's shape -- strategic merge patch,
// JSON patch, a full Pod on update, apply YAML -- the command and args it
// carries are checked for SQL.
func TestEphemeralContainersAreUnmeasuredWithSQLFlag(t *testing.T) {
	// An API server whose dry-run accepts the change: measured as a
	// mutation, this would be REVERSIBLE and allowed.
	var seen []*http.Request
	pod := `{"kind":"Pod","metadata":{"name":"web-1","namespace":"demo"}}`
	e := apiServer(t, pod, pod, 200, &seen)
	e.look = &fakeLook{}
	e.labelsFn = nil
	for _, c := range []struct {
		verb, patchType, body string
		sql                   bool
	}{
		{"patch", "application/strategic-merge-patch+json",
			`{"spec":{"ephemeralContainers":[{"name":"debugger","image":"busybox","command":["sh"],"args":["-c","psql -c 'drop table x'"]}]}}`, true},
		{"patch", "application/json-patch+json",
			`[{"op":"add","path":"/spec/ephemeralContainers/-","value":{"name":"d","image":"postgres","command":["psql"]}}]`, true},
		{"update", "",
			`{"kind":"Pod","spec":{"ephemeralContainers":[{"name":"d","image":"busybox","command":["sleep","3600"]}]}}`, false},
		{"patch", "application/apply-patch+yaml",
			"spec:\n  ephemeralContainers:\n  - name: d\n    command: [mysql, -e, 'delete from t']\n", true},
		{"patch", "application/strategic-merge-patch+json", `{not json`, false},
	} {
		a := normalize.Action{Verb: c.verb, Version: "v1", Resource: "pods", Subresource: "ephemeralcontainers",
			Namespace: "demo", Name: "web-1", PatchType: c.patchType, Principal: alice}
		i := e.Assess(context.Background(), a, []byte(c.body)).Impact
		if i.Measured || i.Class != ClassTerminal || i.SQLDetected != c.sql {
			t.Errorf("%s %s: impact %+v, want unmeasured with sqlDetected=%v", c.verb, c.body, i, c.sql)
		}
	}
}

// Final review I5: a GET that upgrades is a stream, not a read, even on a
// subresource this build has no case for.
func TestUpgradeGETIsUnmeasured(t *testing.T) {
	var seen []*http.Request
	e := apiServer(t, `{"kind":"VirtualMachineInstance"}`, `{}`, 200, &seen)
	e.labelsFn = nil
	a := normalize.Action{Verb: "get", Group: "subresources.kubevirt.io", Version: "v1", Resource: "virtualmachineinstances",
		Subresource: "vnc", Namespace: "demo", Name: "vm", Upgrade: true, Principal: alice}
	if i := e.Assess(context.Background(), a, nil).Impact; i.Measured || i.Class != ClassTerminal {
		t.Errorf("upgrade GET impact %+v", i)
	}
}
