package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunMiniCANoArgs(t *testing.T) {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	err := runMiniCA(nil)
	w.Close()
	os.Stderr = old
	r.Close()
	if err == nil || !strings.Contains(err.Error(), "subcommand required") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestRunMiniCAUnknown(t *testing.T) {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	err := runMiniCA([]string{"voodoo"})
	w.Close()
	os.Stderr = old
	r.Close()
	if err == nil || !strings.Contains(err.Error(), "unknown subcommand") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestRunMiniCAHelp(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "help"} {
		old := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w
		err := runMiniCA([]string{arg})
		w.Close()
		os.Stderr = old
		r.Close()
		if err != nil {
			t.Errorf("help should succeed: %v", err)
		}
	}
}

func TestMiniCAUsage(t *testing.T) {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	miniCAUsage()
	w.Close()
	os.Stderr = old
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	out := string(buf[:n])
	if !strings.Contains(out, "init") || !strings.Contains(out, "issue") {
		t.Errorf("usage missing keywords: %s", out)
	}
}

func TestMiniCAInit(t *testing.T) {
	dir := t.TempDir()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := miniCAInit([]string{"--state-dir", dir, "--trust-domain", "spiffe://test"})
	w.Close()
	os.Stdout = old
	r.Close()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestMiniCAIssueMissingAgentID(t *testing.T) {
	if err := miniCAIssue([]string{"--state-dir", t.TempDir()}); err == nil || !strings.Contains(err.Error(), "agent-id") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestMiniCAIssueMissingState(t *testing.T) {
	if err := miniCAIssue([]string{"--state-dir", "/nonexistent/dir", "--agent-id", "x"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestMiniCARevokeFlow(t *testing.T) {
	stateDir := t.TempDir()
	outDir := t.TempDir()
	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w
	defer func() {
		w.Close()
		os.Stdout = old
	}()

	if err := miniCAInit([]string{"--state-dir", stateDir, "--trust-domain", "spiffe://t"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := miniCAIssue([]string{"--state-dir", stateDir, "--agent-id", "agent1", "--out", outDir, "--trust-domain", "spiffe://t"}); err != nil {
		t.Fatalf("issue: %v", err)
	}

	if err := miniCARevoke([]string{"--state-dir", stateDir, "--trust-domain", "spiffe://t"}); err == nil {
		t.Fatal("expected error when --serial missing")
	}
	if err := miniCARevoke([]string{"--state-dir", "/nonexistent", "--serial", "abc"}); err == nil {
		t.Fatal("expected error on missing state dir")
	}
	if err := miniCARevoke([]string{"--state-dir", stateDir, "--serial", "abcd1234", "--reason", "stolen", "--trust-domain", "spiffe://t"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := miniCAListRevoked([]string{"--state-dir", stateDir, "--trust-domain", "spiffe://t"}); err != nil {
		t.Fatalf("list-revoked: %v", err)
	}
	if err := miniCAListRevoked([]string{"--state-dir", "/nonexistent"}); err == nil {
		t.Fatal("expected error on missing state dir")
	}
}

func TestRunMiniCA_Revoke_Dispatch(t *testing.T) {
	stateDir := t.TempDir()
	if err := miniCAInit([]string{"--state-dir", stateDir, "--trust-domain", "spiffe://t"}); err != nil {
		t.Fatal(err)
	}
	if err := runMiniCA([]string{"revoke", "--state-dir", stateDir, "--serial", "ff", "--trust-domain", "spiffe://t"}); err != nil {
		t.Fatalf("dispatch revoke: %v", err)
	}
	if err := runMiniCA([]string{"list-revoked", "--state-dir", stateDir, "--trust-domain", "spiffe://t"}); err != nil {
		t.Fatalf("dispatch list-revoked: %v", err)
	}
}

func TestMiniCAInitAndIssue(t *testing.T) {
	stateDir := t.TempDir()
	outDir := t.TempDir()
	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w
	defer func() {
		w.Close()
		os.Stdout = old
	}()

	if err := miniCAInit([]string{"--state-dir", stateDir, "--trust-domain", "spiffe://t"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := miniCAIssue([]string{"--state-dir", stateDir, "--agent-id", "agent1", "--out", outDir, "--trust-domain", "spiffe://t"}); err != nil {
		t.Fatalf("issue: %v", err)
	}

	for _, name := range []string{"agent1.crt", "agent1.key", "ca-bundle.pem"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
}
