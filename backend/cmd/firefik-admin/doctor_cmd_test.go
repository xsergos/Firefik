package main

import (
	"strings"
	"testing"
)

func TestCmdDoctorRuns(t *testing.T) {
	out := captureStdout(t, func() {
		_ = cmdDoctor([]string{"--audit-path", "", "--geoip-db", "/nonexistent"})
	})
	if !strings.Contains(out, "PASS") && !strings.Contains(out, "FAIL") {
		t.Errorf("expected PASS or FAIL marker: %s", out)
	}
}

func TestCmdDoctorJSON(t *testing.T) {
	out := captureStdout(t, func() {
		_ = cmdDoctor([]string{"--output", "json"})
	})
	if !strings.Contains(out, `"checks":`) {
		t.Errorf("expected json: %s", out)
	}
}

func TestCmdMetricsAuditStdin(t *testing.T) {
	out := captureStdout(t, func() {
		_ = cmdMetricsAudit([]string{"--source", "/nonexistent/path"})
	})
	_ = out
}

func TestCmdMetricsAuditJSON(t *testing.T) {
	tmp := t.TempDir() + "/m.txt"
	out := captureStdout(t, func() {
		_ = cmdMetricsAudit([]string{"--source", tmp})
	})
	_ = out
}
