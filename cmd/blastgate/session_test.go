package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
)

func tempEnv(t *testing.T) func(string) string {
	dir := t.TempDir()
	return func(k string) string {
		if k == "BLASTGATE_DATA_DIR" {
			return dir
		}
		return ""
	}
}

func TestSessionNewPrintsAWorkingKubeconfig(t *testing.T) {
	env := tempEnv(t)
	var out, errb bytes.Buffer
	code := run([]string{"session", "new", "--human", "alice", "--agent", "coding-agent", "--ttl", "2h", "--namespace", "demo"}, env, &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, errb.String())
	}
	cfg, err := clientcmd.Load(out.Bytes())
	if err != nil {
		t.Fatalf("stdout is not a kubeconfig: %v\n%s", err, out.String())
	}
	ctx := cfg.Contexts[cfg.CurrentContext]
	if cfg.Clusters[ctx.Cluster].Server != "https://127.0.0.1:8443" {
		t.Errorf("server = %q", cfg.Clusters[ctx.Cluster].Server)
	}
	if !strings.HasPrefix(cfg.AuthInfos[ctx.AuthInfo].Token, "bg_") {
		t.Error("token missing")
	}
	if len(cfg.Clusters[ctx.Cluster].CertificateAuthorityData) == 0 {
		t.Error("CA missing")
	}
	if strings.Contains(errb.String(), cfg.AuthInfos[ctx.AuthInfo].Token) {
		t.Error("the token was printed to stderr")
	}
}

func TestSessionListAndRevoke(t *testing.T) {
	env := tempEnv(t)
	var out, errb bytes.Buffer
	run([]string{"session", "new", "--human", "alice", "--agent", "x"}, env, &out, &errb)
	out.Reset()
	if code := run([]string{"session", "list"}, env, &out, &errb); code != 0 {
		t.Fatalf("list exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], "alice") || !strings.Contains(lines[1], "active") {
		t.Fatalf("list:\n%s", out.String())
	}
	id := strings.Fields(lines[1])[0]
	if code := run([]string{"session", "revoke", id}, env, &out, &errb); code != 0 {
		t.Fatalf("revoke exit %d: %s", code, errb.String())
	}
	out.Reset()
	run([]string{"session", "list"}, env, &out, &errb)
	if !strings.Contains(out.String(), "revoked") {
		t.Errorf("list after revoke:\n%s", out.String())
	}
}

func TestSessionRefusals(t *testing.T) {
	env := tempEnv(t)
	for _, args := range [][]string{
		{"session"},
		{"session", "new", "--agent", "x"},
		{"session", "new", "--human", "system:admin", "--agent", "x"},
		{"session", "new", "--human", "alice", "--agent", "x", "--ttl", "0s"},
		{"session", "revoke"},
		{"session", "revoke", "does-not-exist"},
		{"session", "bogus"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, env, &out, &errb); code != 2 {
			t.Errorf("%v: exit = %d, want 2 (%s)", args, code, errb.String())
		}
	}
}

func TestSessionNeedsADataDir(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"session", "list"}, noenv, &out, &errb); code != 2 || !strings.Contains(errb.String(), "BLASTGATE_DATA_DIR") {
		t.Errorf("exit = %d, stderr = %q", code, errb.String())
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// `session new > agent.kubeconfig` on a full disk used to exit 0 with an
// empty file, leaving a live session whose token nobody holds.
func TestSessionNewFailsWhenStdoutFails(t *testing.T) {
	env := tempEnv(t)
	var errb bytes.Buffer
	if code := run([]string{"session", "new", "--human", "alice", "--agent", "x"}, env, failWriter{}, &errb); code != 1 {
		t.Fatalf("exit = %d, want 1: %s", code, errb.String())
	}
	var out bytes.Buffer
	run([]string{"session", "list"}, env, &out, &errb)
	if !strings.Contains(out.String(), "revoked") || strings.Contains(out.String(), "active") {
		t.Errorf("the undelivered session was left live:\n%s", out.String())
	}
}

// Listening on every interface says nothing about the address kubectl
// should dial, so there is no safe --server default.
func TestSessionNewNeedsServerWhenListeningEverywhere(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:8443", "[::]:8443", ":8443"} {
		dir := t.TempDir()
		env := func(k string) string {
			return map[string]string{"BLASTGATE_DATA_DIR": dir, "BLASTGATE_LISTEN": listen, "BLASTGATE_ALLOW_REMOTE": "1"}[k]
		}
		var out, errb bytes.Buffer
		if code := run([]string{"session", "new", "--human", "alice", "--agent", "x"}, env, &out, &errb); code != 2 || !strings.Contains(errb.String(), "--server") || out.Len() != 0 {
			t.Errorf("%s: exit = %d, stdout %d bytes, stderr %q", listen, code, out.Len(), errb.String())
		}
		out.Reset()
		errb.Reset()
		if code := run([]string{"session", "new", "--human", "alice", "--agent", "x", "--server", "https://gate.internal:8443"}, env, &out, &errb); code != 0 {
			t.Errorf("%s with --server: exit = %d: %s", listen, code, errb.String())
		}
	}
}

// A data dir created by hand with the umask's 0755 holds the database and
// the CA key's directory; openStore tightens it rather than trusting it.
func TestAnExistingDataDirIsMadePrivate(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"session", "list"}, func(k string) string {
		if k == "BLASTGATE_DATA_DIR" {
			return dir
		}
		return ""
	}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d: %s", code, errb.String())
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("data dir mode = %v, want 0700", fi.Mode().Perm())
	}
}
