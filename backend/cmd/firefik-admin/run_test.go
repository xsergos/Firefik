package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"testing"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	fn()
	w.Close()
	<-done
	os.Stderr = old
	return buf.String()
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	fn()
	w.Close()
	<-done
	os.Stdout = old
	return buf.String()
}

func TestRunNoArgs(t *testing.T) {
	_ = captureStderr(t, func() {
		err := run([]string{})
		if err == nil {
			t.Errorf("expected error")
		}
	})
}

func TestRunUnknownCommand(t *testing.T) {
	_ = captureStderr(t, func() {
		err := run([]string{"nope"})
		if err == nil || !strings.Contains(err.Error(), "unknown command") {
			t.Errorf("unexpected: %v", err)
		}
	})
}

func TestRunHelpVariants(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "help"} {
		t.Run(arg, func(t *testing.T) {
			out := captureStderr(t, func() {
				if err := run([]string{arg}); err != nil {
					t.Errorf("help should not error: %v", err)
				}
			})
			if !strings.Contains(out, "commands:") {
				t.Errorf("expected commands listing")
			}
		})
	}
}

func TestRunDispatchesInventory(t *testing.T) {
	fb := newFakeBackend()
	fb.listIDs = []string{"abc"}
	defer swapResolveBackend(fb, "iptables")()
	out := captureStdout(t, func() {
		if err := run([]string{"inventory"}); err != nil {
			t.Fatalf("inventory: %v", err)
		}
	})
	if !strings.Contains(out, "tracked containers: 1") {
		t.Errorf("unexpected: %s", out)
	}
}

func TestRunDispatchesStatus(t *testing.T) {
	fb := newFakeBackend()
	defer swapResolveBackend(fb, "iptables")()
	out := captureStdout(t, func() {
		if err := run([]string{"status"}); err != nil {
			t.Fatalf("status: %v", err)
		}
	})
	if !strings.Contains(out, "backend:") {
		t.Errorf("unexpected: %s", out)
	}
}

func TestRunErrorPropagates(t *testing.T) {
	defer swapResolveBackendErr(errors.New("boom"))()
	err := run([]string{"inventory"})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestUsageOutputs(t *testing.T) {
	out := captureStderr(t, func() { usage() })
	for _, want := range []string{"inventory", "status", "check", "drain", "reconcile", "reap", "doctor", "diff", "explain", "enroll", "metrics-audit", "force-reset"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage missing %q", want)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := writeJSON(&buf, map[string]int{"a": 1}); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
	if !strings.Contains(buf.String(), `"a": 1`) {
		t.Errorf("unexpected output: %s", buf.String())
	}
}

func TestParseGlobalsDefaults(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	g := parseGlobals(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if g.chain != defaultChain || g.parent != defaultParent {
		t.Errorf("defaults wrong: %+v", g)
	}
	if g.backend != "auto" || g.output != "text" {
		t.Errorf("backend/output defaults wrong: %+v", g)
	}
}

func TestParseGlobalsOverrides(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	g := parseGlobals(fs)
	if err := fs.Parse([]string{"--chain", "X", "--parent", "Y", "--backend", "nftables", "--output", "json"}); err != nil {
		t.Fatal(err)
	}
	if g.chain != "X" || g.parent != "Y" || g.backend != "nftables" || g.output != "json" {
		t.Errorf("overrides wrong: %+v", g)
	}
}
