package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SaiPisey2/blastgate/internal/store"
)

func approverEnv(t *testing.T) (func(string) string, string) {
	dir := t.TempDir()
	return func(k string) string { return map[string]string{"BLASTGATE_DATA_DIR": dir}[k] }, dir
}

// approverNewToken runs `approver new --name name` and returns its token.
func approverNewToken(t *testing.T, env func(string) string, name string) string {
	t.Helper()
	var out, errb bytes.Buffer
	if code := run([]string{"approver", "new", "--name", name}, env, &out, &errb); code != 0 {
		t.Fatalf("approver new: exit %d: %s", code, errb.String())
	}
	return strings.TrimSuffix(out.String(), "\n")
}

func TestApproverNewPrintsTokenOnlyToStdout(t *testing.T) {
	env, dir := approverEnv(t)
	var out, errb bytes.Buffer
	if code := run([]string{"approver", "new", "--name", "bob"}, env, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	tok, ok := strings.CutSuffix(out.String(), "\n")
	// Exactly the token and a newline: `> bob.token` must hold nothing
	// else, and a script reading stdout must get nothing else.
	if !ok || strings.ContainsAny(tok, " \t\n") || !strings.HasPrefix(tok, "bga_") || len(tok) != len("bga_")+43 {
		t.Fatalf("stdout = %q, want bga_ + 43 base64url characters and a newline", out.String())
	}
	if strings.Contains(errb.String(), tok) || strings.Contains(errb.String(), tok[4:]) {
		t.Errorf("the token reached stderr: %s", errb.String())
	}
	if !strings.Contains(errb.String(), "bob") {
		t.Errorf("stderr has no summary naming the approver: %q", errb.String())
	}
	st, err := store.Open(filepath.Join(dir, "blastgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := sha256.Sum256([]byte(tok))
	a, err := st.ApproverByTokenHash(context.Background(), h[:])
	if err != nil || a.Name != "bob" || !a.Revoked.IsZero() {
		t.Errorf("stored approver = %+v, %v; want bob, live, found by the token's hash", a, err)
	}
}

func TestApproverNamesAreValidatedLikeHumans(t *testing.T) {
	env, _ := approverEnv(t)
	for _, name := range []string{"", "system:admin", "bob smith", "bob\r\nX-Evil: 1", strings.Repeat("a", 254)} {
		var out, errb bytes.Buffer
		if code := run([]string{"approver", "new", "--name", name}, env, &out, &errb); code != 2 || out.Len() != 0 {
			t.Errorf("name %q: exit %d, stdout %q; want 2 and no token", name, code, out.String())
		}
	}
	var out bytes.Buffer
	run([]string{"approver", "list"}, env, &out, &bytes.Buffer{})
	if strings.Count(out.String(), "\n") != 1 {
		t.Errorf("a refused name was stored:\n%s", out.String())
	}
}

func TestApproverListAndRevoke(t *testing.T) {
	env, dir := approverEnv(t)
	tok := approverNewToken(t, env, "bob")
	approverNewToken(t, env, "carol")
	// Two live approvers cannot share a name.
	var out, errb bytes.Buffer
	if code := run([]string{"approver", "new", "--name", "bob"}, env, &out, &errb); code != 1 || out.Len() != 0 {
		t.Errorf("duplicate bob: exit %d, stdout %q", code, out.String())
	}

	out.Reset()
	if code := run([]string{"approver", "list"}, env, &out, &errb); code != 0 {
		t.Fatalf("list: exit %d", code)
	}
	var bobID string
	for _, l := range strings.Split(out.String(), "\n") {
		if f := strings.Fields(l); len(f) == 4 && f[1] == "bob" {
			bobID = f[0]
			if f[3] != "active" {
				t.Errorf("bob listed as %s", f[3])
			}
		}
	}
	if bobID == "" || strings.Contains(out.String(), tok) {
		t.Fatalf("list lacks bob, or shows a token:\n%s", out.String())
	}

	errb.Reset()
	if code := run([]string{"approver", "revoke", bobID}, env, &bytes.Buffer{}, &errb); code != 0 {
		t.Fatalf("revoke: exit %d: %s", code, errb.String())
	}
	out.Reset()
	run([]string{"approver", "list"}, env, &out, &bytes.Buffer{})
	if !strings.Contains(out.String(), bobID) || !strings.Contains(out.String(), "revoked") {
		t.Errorf("after revoke:\n%s", out.String())
	}
	st, err := store.Open(filepath.Join(dir, "blastgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(tok))
	a, err := st.ApproverByTokenHash(context.Background(), h[:])
	st.Close()
	if err != nil || a.Revoked.IsZero() {
		t.Errorf("bob after revoke = %+v, %v", a, err)
	}

	errb.Reset()
	if code := run([]string{"approver", "revoke", "0000000000000000"}, env, &bytes.Buffer{}, &errb); code != 1 || !strings.Contains(errb.String(), "no approver") {
		t.Errorf("unknown id: exit %d: %s", code, errb.String())
	}
	// A revoked name is free again.
	approverNewToken(t, env, "bob")
}

func TestApproverUsage(t *testing.T) {
	env, _ := approverEnv(t)
	for _, args := range [][]string{{"approver"}, {"approver", "frob"}, {"approver", "revoke"}, {"approver", "list", "x"}, {"approver", "new", "--name", "bob", "extra"}} {
		var out, errb bytes.Buffer
		if code := run(args, env, &out, &errb); code != 2 || out.Len() != 0 {
			t.Errorf("%v: exit %d, stdout %q", args, code, out.String())
		}
	}
	if code := run([]string{"approver", "list"}, noenv, &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
		t.Errorf("no data dir: exit %d, want 2", code)
	}
}

// A token nobody received must not stay a live login.
func TestApproverNewRevokesWhenTheTokenCannotBePrinted(t *testing.T) {
	env, dir := approverEnv(t)
	var errb bytes.Buffer
	if code := run([]string{"approver", "new", "--name", "bob"}, env, failWriter{}, &errb); code != 1 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	st, err := store.Open(filepath.Join(dir, "blastgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	l, err := st.ListApprovers(context.Background())
	if err != nil || len(l) != 1 || l[0].Revoked.IsZero() {
		t.Errorf("approvers = %+v, %v; want bob, revoked", l, err)
	}
}
