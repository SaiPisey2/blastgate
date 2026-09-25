package main

import (
	"bytes"
	"strings"
	"testing"
)

func noenv(string) string { return "" }

func TestNoCommandIsAUsageError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, noenv, &out, &errb); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "usage:") {
		t.Errorf("stderr lacks usage: %q", errb.String())
	}
}

func TestVersionPrints(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, noenv, &out, &errb); code != 0 {
		t.Errorf("exit = %d", code)
	}
	if strings.TrimSpace(out.String()) == "" {
		t.Error("version printed nothing")
	}
}

func TestUnknownCommandIsRefused(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"frobnicate"}, noenv, &out, &errb); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "frobnicate") {
		t.Errorf("refusal must name the command: %q", errb.String())
	}
}
