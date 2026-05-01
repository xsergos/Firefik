package main

import (
	"errors"
	"log/slog"
	"strings"
	"testing"

	"firefik/internal/rules"
)

func TestCmdInventoryText(t *testing.T) {
	fb := newFakeBackend()
	fb.listIDs = []string{"abc123def456", "deadbeef0001"}
	defer swapResolveBackend(fb, "iptables")()

	out := captureStdout(t, func() {
		if err := cmdInventory(nil); err != nil {
			t.Fatalf("inventory: %v", err)
		}
	})
	if !strings.Contains(out, "tracked containers: 2") {
		t.Errorf("missing count: %s", out)
	}
	if !strings.Contains(out, "abc123def456") {
		t.Errorf("missing id: %s", out)
	}
}

func TestCmdInventoryJSON(t *testing.T) {
	fb := newFakeBackend()
	fb.listIDs = []string{"id1"}
	defer swapResolveBackend(fb, "nftables")()

	out := captureStdout(t, func() {
		if err := cmdInventory([]string{"--output", "json"}); err != nil {
			t.Fatalf("inventory: %v", err)
		}
	})
	if !strings.Contains(out, `"backend": "nftables"`) {
		t.Errorf("missing backend in json: %s", out)
	}
}

func TestCmdInventoryListErr(t *testing.T) {
	fb := newFakeBackend()
	fb.listErr = errors.New("listfail")
	defer swapResolveBackend(fb, "iptables")()
	err := cmdInventory(nil)
	if err == nil || !strings.Contains(err.Error(), "enumerate chains") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestCmdInventoryResolveErr(t *testing.T) {
	defer swapResolveBackendErr(errors.New("nobackend"))()
	if err := cmdInventory(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdStatusText(t *testing.T) {
	fb := newFakeBackend()
	fb.listIDs = []string{"x"}
	defer swapResolveBackend(fb, "iptables")()
	out := captureStdout(t, func() {
		if err := cmdStatus(nil); err != nil {
			t.Fatalf("status: %v", err)
		}
	})
	if !strings.Contains(out, "container chains:  1") {
		t.Errorf("got %q", out)
	}
}

func TestCmdStatusJSON(t *testing.T) {
	fb := newFakeBackend()
	defer swapResolveBackend(fb, "iptables")()
	out := captureStdout(t, func() {
		_ = cmdStatus([]string{"--output", "json"})
	})
	if !strings.Contains(out, `"backend": "iptables"`) {
		t.Errorf("got %q", out)
	}
}

func TestCmdStatusListErr(t *testing.T) {
	fb := newFakeBackend()
	fb.listErr = errors.New("oops")
	defer swapResolveBackend(fb, "iptables")()
	if err := cmdStatus(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdStatusResolveErr(t *testing.T) {
	defer swapResolveBackendErr(errors.New("nobackend"))()
	if err := cmdStatus(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdCheckHealthy(t *testing.T) {
	fb := newFakeBackend()
	fb.healthReport = rules.HealthReport{
		Backend:           "iptables",
		ParentJumpPresent: true,
		BaseChainPresent:  true,
	}
	defer swapResolveBackend(fb, "iptables")()
	_ = captureStdout(t, func() {
		if err := cmdCheck(nil); err != nil {
			t.Fatalf("check: %v", err)
		}
	})
}

func TestCmdCheckJSON(t *testing.T) {
	fb := newFakeBackend()
	fb.healthReport = rules.HealthReport{Backend: "iptables", ParentJumpPresent: true, BaseChainPresent: true, Notes: []string{"ok"}}
	defer swapResolveBackend(fb, "iptables")()
	out := captureStdout(t, func() {
		_ = cmdCheck([]string{"--output", "json"})
	})
	if !strings.Contains(out, `"base_chain_present": true`) {
		t.Errorf("got %q", out)
	}
}

func TestCmdCheckHealthyErr(t *testing.T) {
	fb := newFakeBackend()
	fb.healthErr = errors.New("hcfail")
	defer swapResolveBackend(fb, "iptables")()
	if err := cmdCheck(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdCheckResolveErr(t *testing.T) {
	defer swapResolveBackendErr(errors.New("nobackend"))()
	if err := cmdCheck(nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdDrainSystemChain(t *testing.T) {
	err := cmdDrain([]string{"--chain", "DOCKER-USER", "--confirm"})
	if err == nil || !strings.Contains(err.Error(), "system chain") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestCmdDrainResolveErr(t *testing.T) {
	defer swapResolveBackendErr(errors.New("nobackend"))()
	if err := cmdDrain([]string{"--confirm"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdDrainNoChainsKeepParent(t *testing.T) {
	fb := newFakeBackend()
	defer swapResolveBackend(fb, "iptables")()
	out := captureStdout(t, func() {
		if err := cmdDrain([]string{"--confirm", "--keep-parent-jump"}); err != nil {
			t.Fatalf("drain: %v", err)
		}
	})
	if !strings.Contains(out, "no container chains present") {
		t.Errorf("got %q", out)
	}
}

func TestCmdDrainSuccess(t *testing.T) {
	fb := newFakeBackend()
	fb.listIDs = []string{"a", "b"}
	defer swapResolveBackend(fb, "iptables")()
	out := captureStdout(t, func() {
		if err := cmdDrain([]string{"--yes"}); err != nil {
			t.Fatalf("drain: %v", err)
		}
	})
	if fb.removeCalls != 2 {
		t.Errorf("remove calls = %d, want 2", fb.removeCalls)
	}
	if fb.cleanupCalls != 1 {
		t.Errorf("cleanup calls = %d, want 1", fb.cleanupCalls)
	}
	if !strings.Contains(out, "drained 2 chain") {
		t.Errorf("got %q", out)
	}
}

func TestCmdDrainKeepParentSuccess(t *testing.T) {
	fb := newFakeBackend()
	fb.listIDs = []string{"a"}
	defer swapResolveBackend(fb, "iptables")()
	_ = captureStdout(t, func() {
		if err := cmdDrain([]string{"--confirm", "--keep-parent-jump"}); err != nil {
			t.Fatalf("drain: %v", err)
		}
	})
	if fb.cleanupCalls != 0 {
		t.Errorf("cleanup should not be called when --keep-parent-jump")
	}
}

func TestCmdDrainListErr(t *testing.T) {
	fb := newFakeBackend()
	fb.listErr = errors.New("listfail")
	defer swapResolveBackend(fb, "iptables")()
	if err := cmdDrain([]string{"--confirm"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdDrainRemoveErrors(t *testing.T) {
	fb := newFakeBackend()
	fb.listIDs = []string{"a", "b"}
	fb.removeErr = errors.New("rmfail")
	defer swapResolveBackend(fb, "iptables")()
	_ = captureStdout(t, func() {
		err := cmdDrain([]string{"--confirm", "--keep-parent-jump"})
		if err == nil || !strings.Contains(err.Error(), "drain completed with") {
			t.Errorf("expected aggregated error, got %v", err)
		}
	})
}

func TestCmdDrainCleanupErr(t *testing.T) {
	fb := newFakeBackend()
	fb.listIDs = []string{"a"}
	fb.cleanupErr = errors.New("cleanupfail")
	defer swapResolveBackend(fb, "iptables")()
	_ = captureStdout(t, func() {
		err := cmdDrain([]string{"--confirm"})
		if err == nil || !strings.Contains(err.Error(), "base chain teardown") {
			t.Errorf("expected cleanup error, got %v", err)
		}
	})
}

func TestKeepParentSummary(t *testing.T) {
	if got := keepParentSummary(true); got != "retained" {
		t.Errorf("got %q", got)
	}
	if got := keepParentSummary(false); got != "removed" {
		t.Errorf("got %q", got)
	}
}

func TestCmdForceResetSystemChainBlocked(t *testing.T) {
	err := cmdForceReset([]string{"--chain", "INPUT", "--confirm"})
	if err == nil || !strings.Contains(err.Error(), "refusing to reset system chain") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestCmdForceResetEmpty(t *testing.T) {
	fb := newFakeBackend()
	defer swapResolveBackend(fb, "iptables")()
	out := captureStdout(t, func() {
		if err := cmdForceReset([]string{"--confirm"}); err != nil {
			t.Fatalf("force-reset: %v", err)
		}
	})
	if !strings.Contains(out, "no firefik chains present") {
		t.Errorf("got %q", out)
	}
}

func TestCmdForceResetWithChains(t *testing.T) {
	fb := newFakeBackend()
	fb.listIDs = []string{"a"}
	defer swapResolveBackend(fb, "iptables")()
	out := captureStdout(t, func() {
		if err := cmdForceReset([]string{"--yes"}); err != nil {
			t.Fatalf("force-reset: %v", err)
		}
	})
	if fb.removeCalls != 1 {
		t.Errorf("expected 1 remove, got %d", fb.removeCalls)
	}
	if !strings.Contains(out, "removed 1 container chains") {
		t.Errorf("got %q", out)
	}
}

func TestCmdForceResetAllowedSystemChain(t *testing.T) {
	fb := newFakeBackend()
	defer swapResolveBackend(fb, "iptables")()
	_ = captureStdout(t, func() {
		if err := cmdForceReset([]string{"--chain", "DOCKER-USER", "--allow-system-chain", "--confirm"}); err != nil {
			t.Fatalf("force-reset: %v", err)
		}
	})
}

func TestCmdForceResetResolveErr(t *testing.T) {
	defer swapResolveBackendErr(errors.New("nobackend"))()
	err := cmdForceReset([]string{"--confirm"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdForceResetListErr(t *testing.T) {
	fb := newFakeBackend()
	fb.listErr = errors.New("oops")
	defer swapResolveBackend(fb, "iptables")()
	err := cmdForceReset([]string{"--confirm"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdReapDryRun(t *testing.T) {
	fb := newFakeBackend()
	fb.listIDs = []string{"abc"}
	defer swapNewBackendForChain(fb, "iptables")()
	out := captureStdout(t, func() {
		if err := cmdReap([]string{"--suffix", "v1", "--dry-run"}); err != nil {
			t.Fatalf("reap: %v", err)
		}
	})
	if !strings.Contains(out, "dry-run") {
		t.Errorf("got %q", out)
	}
	if fb.cleanupCalls != 0 {
		t.Errorf("cleanup must not be called in dry-run")
	}
}

func TestCmdReapApply(t *testing.T) {
	fb := newFakeBackend()
	fb.listIDs = []string{"abc"}
	defer swapNewBackendForChain(fb, "iptables")()
	_ = captureStdout(t, func() {
		if err := cmdReap([]string{"--suffix", "v1"}); err != nil {
			t.Fatalf("reap: %v", err)
		}
	})
	if fb.cleanupCalls != 1 {
		t.Errorf("expected cleanup called once, got %d", fb.cleanupCalls)
	}
}

func TestCmdReapJSON(t *testing.T) {
	fb := newFakeBackend()
	fb.listIDs = []string{"abc"}
	defer swapNewBackendForChain(fb, "iptables")()
	out := captureStdout(t, func() {
		_ = cmdReap([]string{"--suffix", "v1", "--dry-run", "--output", "json"})
	})
	if !strings.Contains(out, `"would_remove": 1`) {
		t.Errorf("got %q", out)
	}
}

func TestCmdReapListErr(t *testing.T) {
	fb := newFakeBackend()
	fb.listErr = errors.New("listfail")
	defer swapNewBackendForChain(fb, "iptables")()
	err := cmdReap([]string{"--suffix", "v1"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdReapCleanupErr(t *testing.T) {
	fb := newFakeBackend()
	fb.cleanupErr = errors.New("cleanupfail")
	defer swapNewBackendForChain(fb, "iptables")()
	err := cmdReap([]string{"--suffix", "v1"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdReapResolveErr(t *testing.T) {
	prev := newBackendForChainFn
	newBackendForChainFn = func(g *globalFlags, chain string, logger *slog.Logger) (rules.Backend, string, error) {
		return nil, "", errors.New("init failed")
	}
	defer func() { newBackendForChainFn = prev }()
	if err := cmdReap([]string{"--suffix", "v1"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdReconcileResolveErr(t *testing.T) {
	defer swapResolveBackendErr(errors.New("nobackend"))()
	if err := cmdReconcile([]string{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestCmdReconcileBadFlag(t *testing.T) {
	if err := cmdReconcile([]string{"--no-such-flag"}); err == nil {
		t.Fatal("expected flag parse error")
	}
}

func TestCmdReconcileBadRulesFile(t *testing.T) {
	fb := newFakeBackend()
	defer swapResolveBackend(fb, "iptables")()
	err := cmdReconcile([]string{"--rules-file", "../../../etc/passwd"})
	if err == nil {
		return
	}
}
