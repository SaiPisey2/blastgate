package engine

import (
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
	} {
		if !detectSQL(c) {
			t.Errorf("missed %q", c)
		}
	}
}
