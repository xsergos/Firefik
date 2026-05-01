//go:build integration

package integration

import (
	"net"
	"strings"
	"testing"
)

func TestIPTables_SetupChains_CreatesChainAndJump(t *testing.T) {
	requireRoot(t)
	chain := testChainName(t)
	b := newIPTablesBackend(t, chain)
	setupAndDefer(t, b)

	save := iptablesSave(t)
	assertContains(t, save, ":"+chain+" - ")
	assertContains(t, save, "-A FORWARD -j "+chain)
}

func TestIPTables_ApplyContainerRules_EmitsPortRules(t *testing.T) {
	requireRoot(t)
	chain := testChainName(t)
	b := newIPTablesBackend(t, chain)
	setupAndDefer(t, b)

	containerID := "abcdef012345000000000000000000000000000000000000000000000000aaaa"
	ips := []net.IP{net.ParseIP("10.244.0.2")}
	if err := b.ApplyContainerRules(containerID, "nginx", ips, sampleRuleSet(), "DROP", nil); err != nil {
		t.Fatalf("ApplyContainerRules: %v", err)
	}

	save := iptablesSave(t)
	assertContains(t, save, chain+"-abcdef012345")
	assertContains(t, save, "10.244.0.2")
	assertContains(t, save, "--dport 443")
	assertContains(t, save, "--dport 80")
}

func TestIPTables_RemoveContainerChains_LeavesBaseChain(t *testing.T) {
	requireRoot(t)
	chain := testChainName(t)
	b := newIPTablesBackend(t, chain)
	setupAndDefer(t, b)

	containerID := "abcdef012345000000000000000000000000000000000000000000000000aaaa"
	ips := []net.IP{net.ParseIP("10.244.0.2")}
	if err := b.ApplyContainerRules(containerID, "nginx", ips, sampleRuleSet(), "DROP", nil); err != nil {
		t.Fatalf("ApplyContainerRules: %v", err)
	}
	if err := b.RemoveContainerChains(containerID); err != nil {
		t.Fatalf("RemoveContainerChains: %v", err)
	}

	save := iptablesSave(t)
	assertNotContains(t, save, chain+"-abcdef012345")
	assertContains(t, save, ":"+chain+" - ")
}

func TestIPTables_Cleanup_RemovesBaseChainAndJump(t *testing.T) {
	requireRoot(t)
	chain := testChainName(t)
	b := newIPTablesBackend(t, chain)
	if err := b.SetupChains(); err != nil {
		t.Fatalf("SetupChains: %v", err)
	}

	if err := b.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	save := iptablesSave(t)
	if strings.Contains(save, ":"+chain+" - ") {
		t.Errorf("base chain %s still present after Cleanup:\n%s", chain, save)
	}
	if strings.Contains(save, "-A FORWARD -j "+chain) {
		t.Errorf("parent jump to %s still present after Cleanup", chain)
	}
}
