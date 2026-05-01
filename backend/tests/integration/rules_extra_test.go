//go:build integration

package integration

import (
	"net"
	"testing"

	"firefik/internal/docker"
	"firefik/internal/rules"
)

func sampleRuleSetWithRateLimitAndLog() []docker.FirewallRuleSet {
	return []docker.FirewallRuleSet{
		{
			Name:      "api",
			Ports:     []uint16{443},
			Protocol:  "tcp",
			Allowlist: []net.IPNet{mustCIDR("10.0.0.0/8")},
			RateLimit: &docker.RateLimitConfig{Rate: 10, Burst: 20},
			Log:       true,
			LogPrefix: "FIREFIK-API",
		},
	}
}

func TestIPTables_ApplyContainerRules_WithRateLimitAndLog(t *testing.T) {
	requireRoot(t)
	chain := testChainName(t)
	b := newIPTablesBackend(t, chain)
	setupAndDefer(t, b)

	cid := "abcdef012345000000000000000000000000000000000000000000000000aaaa"
	ips := []net.IP{net.ParseIP("10.244.0.7")}
	if err := b.ApplyContainerRules(cid, "api-srv", ips, sampleRuleSetWithRateLimitAndLog(), "DROP", nil); err != nil {
		t.Fatalf("ApplyContainerRules: %v", err)
	}

	save := iptablesSave(t)
	assertContains(t, save, "10.244.0.7")
	assertContains(t, save, "--dport 443")
	assertContains(t, save, "limit")
	assertContains(t, save, "NFLOG")
}

func TestNFTables_ApplyContainerRules_WithRateLimitAndLog(t *testing.T) {
	requireRoot(t)
	chain := testChainName(t)
	b := newNFTablesBackend(t, chain)
	setupAndDefer(t, b)

	cid := "abcdef012345000000000000000000000000000000000000000000000000aaaa"
	ips := []net.IP{net.ParseIP("10.244.0.8")}
	if err := b.ApplyContainerRules(cid, "api-srv", ips, sampleRuleSetWithRateLimitAndLog(), "DROP", nil); err != nil {
		t.Fatalf("ApplyContainerRules: %v", err)
	}

	out := nftListRuleset(t)
	assertContains(t, out, "10.244.0.8")
	assertContains(t, out, "limit")
}

func TestIPTables_Healthy_ReturnsReportWhenChainExists(t *testing.T) {
	requireRoot(t)
	chain := testChainName(t)
	b := newIPTablesBackend(t, chain)
	setupAndDefer(t, b)

	rep, err := b.Healthy()
	if err != nil {
		t.Fatalf("Healthy: %v", err)
	}
	if rep.Backend != "iptables" {
		t.Errorf("backend=%q want iptables", rep.Backend)
	}
	if !rep.BaseChainPresent {
		t.Errorf("BaseChainPresent should be true after SetupChains")
	}
}

func TestNFTables_Healthy_ReturnsReportWhenTableExists(t *testing.T) {
	requireRoot(t)
	chain := testChainName(t)
	b := newNFTablesBackend(t, chain)
	setupAndDefer(t, b)

	rep, err := b.Healthy()
	if err != nil {
		t.Fatalf("Healthy: %v", err)
	}
	if rep.Backend != "nftables" {
		t.Errorf("backend=%q want nftables", rep.Backend)
	}
	if !rep.BaseChainPresent {
		t.Errorf("BaseChainPresent should be true")
	}
}

func TestDetectBackendType_PrefersNFTablesWhenAvailable(t *testing.T) {
	requireRoot(t)
	got := rules.DetectBackendType()
	if got != "iptables" && got != "nftables" {
		t.Errorf("unexpected backend type: %q", got)
	}
}
