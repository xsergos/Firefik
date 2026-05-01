package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseEventList_Default(t *testing.T) {
	got := parseEventList("")
	want := []string{
		"policy_approval_requested",
		"policy_approval_approved",
		"policy_approval_rejected",
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d", len(got))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseEventList_Explicit(t *testing.T) {
	got := parseEventList("a, b ,, c ")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("got %#v", got)
	}
}

func TestParseDurationOr(t *testing.T) {
	if got := parseDurationOr("10s", time.Second); got != 10*time.Second {
		t.Errorf("explicit = %v", got)
	}
	if got := parseDurationOr("garbage", 7*time.Second); got != 7*time.Second {
		t.Errorf("garbage -> fallback = %v", got)
	}
	if got := parseDurationOr("0s", 5*time.Second); got != 5*time.Second {
		t.Errorf("zero -> fallback = %v", got)
	}
}

func TestServerEnvWithFile(t *testing.T) {
	t.Setenv("TEST_X", "")
	t.Setenv("TEST_X_FILE", "")
	if got := serverEnvWithFile("TEST_X", "TEST_X_FILE"); got != "" {
		t.Errorf("empty -> %q", got)
	}
	t.Setenv("TEST_X", "direct")
	if got := serverEnvWithFile("TEST_X", "TEST_X_FILE"); got != "direct" {
		t.Errorf("direct = %q", got)
	}
	t.Setenv("TEST_X", "")
	dir := t.TempDir()
	fp := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(fp, []byte("from-file\n  "), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_X_FILE", fp)
	if got := serverEnvWithFile("TEST_X", "TEST_X_FILE"); got != "from-file" {
		t.Errorf("from file = %q", got)
	}
	t.Setenv("TEST_X_FILE", filepath.Join(dir, "absent"))
	if got := serverEnvWithFile("TEST_X", "TEST_X_FILE"); got != "" {
		t.Errorf("absent file = %q", got)
	}
}

func TestBuildServerAudit_NoEnvNoSinks(t *testing.T) {
	t.Setenv("FIREFIK_WEBHOOK_URL", "")
	t.Setenv("FIREFIK_OTEL_LOGS_ENABLED", "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fan := buildServerAudit(logger)
	if fan == nil {
		t.Fatal("expected non-nil fan")
	}
	if len(fan.Sinks) != 0 {
		t.Errorf("expected empty, got %d", len(fan.Sinks))
	}
}

func TestBuildServerAudit_WebhookSink(t *testing.T) {
	t.Setenv("FIREFIK_WEBHOOK_URL", "https://example.com/hook")
	t.Setenv("FIREFIK_WEBHOOK_EVENTS", "policy_approval_requested")
	t.Setenv("FIREFIK_OTEL_LOGS_ENABLED", "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fan := buildServerAudit(logger)
	if len(fan.Sinks) != 1 {
		t.Fatalf("expected 1 sink, got %d", len(fan.Sinks))
	}
}

func TestBuildServerAudit_OTelSink(t *testing.T) {
	t.Setenv("FIREFIK_WEBHOOK_URL", "")
	t.Setenv("FIREFIK_OTEL_LOGS_ENABLED", "true")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fan := buildServerAudit(logger)
	if len(fan.Sinks) != 1 {
		t.Fatalf("expected 1 sink, got %d", len(fan.Sinks))
	}
}

func TestBuildServerAudit_BothSinks(t *testing.T) {
	t.Setenv("FIREFIK_WEBHOOK_URL", "https://example.com/hook")
	t.Setenv("FIREFIK_OTEL_LOGS_ENABLED", "true")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fan := buildServerAudit(logger)
	if len(fan.Sinks) != 2 {
		t.Fatalf("expected 2 sinks, got %d", len(fan.Sinks))
	}
}
