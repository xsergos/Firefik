package audit

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
)

type capturingLogger struct {
	embedded.Logger
	records []log.Record
}

func (c *capturingLogger) Emit(_ context.Context, rec log.Record) {
	c.records = append(c.records, rec)
}

func (c *capturingLogger) Enabled(_ context.Context, _ log.EnabledParameters) bool { return true }

func TestOTelSink_WriteEmitsRecord(t *testing.T) {
	cap := &capturingLogger{}
	s := &OTelSink{logger: cap}
	ev := Event{
		Timestamp:     time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Action:        "rule_applied",
		Source:        "agent",
		ContainerID:   "abc123",
		ContainerName: "test-container",
		DefaultPolicy: "DROP",
		RuleSets:      3,
		Metadata:      map[string]string{"k": "v"},
	}
	if err := s.Write(ev); err != nil {
		t.Fatal(err)
	}
	if len(cap.records) != 1 {
		t.Fatalf("records = %d", len(cap.records))
	}
	rec := cap.records[0]
	if rec.Severity() != log.SeverityInfo {
		t.Errorf("severity = %v", rec.Severity())
	}
	if rec.SeverityText() != "INFO" {
		t.Errorf("severity text = %q", rec.SeverityText())
	}
}

func TestOTelSink_WriteFailureSeverity(t *testing.T) {
	cap := &capturingLogger{}
	s := &OTelSink{logger: cap}
	if err := s.Write(Event{Action: "rule_apply_failed"}); err != nil {
		t.Fatal(err)
	}
	if got := cap.records[0].Severity(); got != log.SeverityError {
		t.Errorf("severity = %v", got)
	}
}

func TestOTelSink_WriteWarnSeverity(t *testing.T) {
	cap := &capturingLogger{}
	s := &OTelSink{logger: cap}
	if err := s.Write(Event{Action: "policy_approval_rejected"}); err != nil {
		t.Fatal(err)
	}
	if got := cap.records[0].Severity(); got != log.SeverityWarn {
		t.Errorf("severity = %v", got)
	}
}

func TestOTelSink_WriteZeroTimeUsesNow(t *testing.T) {
	cap := &capturingLogger{}
	s := &OTelSink{logger: cap}
	before := time.Now().UTC()
	if err := s.Write(Event{Action: "x"}); err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC()
	got := cap.records[0].Timestamp()
	if got.Before(before) || got.After(after.Add(time.Second)) {
		t.Errorf("ts = %v not in [%v, %v]", got, before, after)
	}
}

func TestOTelSink_WriteNoLoggerNoOp(t *testing.T) {
	s := &OTelSink{logger: nil}
	if err := s.Write(Event{Action: "x"}); err != nil {
		t.Fatal(err)
	}
}

func TestOTelSink_Close(t *testing.T) {
	s := NewOTelSink()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSeverityForAction(t *testing.T) {
	cases := map[string]log.Severity{
		"rule_applied":             log.SeverityInfo,
		"rule_apply_failed":        log.SeverityError,
		"rule_drift_detected":      log.SeverityWarn,
		"policy_approval_rejected": log.SeverityWarn,
		"unknown":                  log.SeverityInfo,
	}
	for action, want := range cases {
		if got := severityForAction(action); got != want {
			t.Errorf("severityForAction(%q) = %v, want %v", action, got, want)
		}
	}
}

func TestSeverityTextForAction(t *testing.T) {
	cases := map[string]string{
		"rule_apply_failed":        "ERROR",
		"policy_approval_rejected": "WARN",
		"rule_applied":             "INFO",
	}
	for action, want := range cases {
		if got := severityTextForAction(action); got != want {
			t.Errorf("severityTextForAction(%q) = %q, want %q", action, got, want)
		}
	}
}
