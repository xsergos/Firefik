package main

import (
	"strings"
	"testing"
)

func TestCmdReapMissingSuffix(t *testing.T) {
	err := cmdReap([]string{})
	if err == nil {
		t.Fatal("want error when --suffix missing")
	}
	if !strings.Contains(err.Error(), "--suffix is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCmdReapInvalidSuffix(t *testing.T) {
	err := cmdReap([]string{"--suffix", "bad suffix!!"})
	if err == nil {
		t.Fatal("want error on invalid suffix")
	}
	if !strings.Contains(err.Error(), "must match") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCmdReapRejectsSystemChainViaSuffix(t *testing.T) {
	err := cmdReap([]string{"--chain", "DOCKER", "--suffix", "USER"})
	if err == nil {
		t.Fatal("want error on system chain composition")
	}
	if !strings.Contains(err.Error(), "system chain") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReapReportJSONShape(t *testing.T) {
	rep := reapReport{
		Backend:      "nftables",
		Chain:        "FIREFIK",
		Suffix:       "v1",
		LegacyChain:  "FIREFIK-v1",
		DryRun:       true,
		ContainerIDs: []string{"abc123", "def456"},
		WouldRemove:  2,
	}
	if rep.Backend != "nftables" || rep.WouldRemove != 2 {
		t.Errorf("report fields mismatch: %+v", rep)
	}
}
