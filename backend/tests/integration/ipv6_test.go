//go:build integration

package integration

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"firefik/internal/audit"
	"firefik/internal/config"
	"firefik/internal/docker"
	"firefik/internal/rules"
)

func ip6tablesSave(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "ip6tables-save", "-t", "filter").Output()
	if err != nil {
		t.Fatalf("ip6tables-save failed: %v", err)
	}
	return string(out)
}

func newIP6TablesBackend(t *testing.T, chain string) rules.Backend {
	t.Helper()
	b, err := rules.NewIP6TablesBackend(chain, "FORWARD")
	if err != nil {
		t.Fatalf("NewIP6TablesBackend(%s): %v", chain, err)
	}
	return b
}

func sampleRuleSetIPv6() []docker.FirewallRuleSet {
	_, ipv6Net, _ := net.ParseCIDR("2001:db8::/32")
	return []docker.FirewallRuleSet{
		{
			Name:      "web6",
			Ports:     []uint16{80, 443},
			Protocol:  "tcp",
			Allowlist: []net.IPNet{*ipv6Net},
		},
	}
}

func TestIP6Tables_SetupChains_CreatesChain(t *testing.T) {
	requireRoot(t)
	chain := testChainName(t)
	b := newIP6TablesBackend(t, chain)
	setupAndDefer(t, b)

	save := ip6tablesSave(t)
	assertContains(t, save, ":"+chain+" - ")
	assertContains(t, save, "-A FORWARD -j "+chain)
}

func TestIP6Tables_ApplyContainerRules_EmitsPortRules(t *testing.T) {
	requireRoot(t)
	chain := testChainName(t)
	b := newIP6TablesBackend(t, chain)
	setupAndDefer(t, b)

	containerID := "abcdef012345000000000000000000000000000000000000000000000000aaaa"
	ips := []net.IP{net.ParseIP("2001:db8::2")}
	if err := b.ApplyContainerRules(containerID, "nginx6", ips, sampleRuleSetIPv6(), "DROP", nil); err != nil {
		t.Fatalf("ApplyContainerRules: %v", err)
	}

	save := ip6tablesSave(t)
	assertContains(t, save, chain+"-abcdef012345")
	assertContains(t, save, "2001:db8::2")
	assertContains(t, save, "--dport 443")
	assertContains(t, save, "--dport 80")
}

func TestIP6Tables_RemoveContainerChains_LeavesBaseChain(t *testing.T) {
	requireRoot(t)
	chain := testChainName(t)
	b := newIP6TablesBackend(t, chain)
	setupAndDefer(t, b)

	containerID := "abcdef012345000000000000000000000000000000000000000000000000aaaa"
	ips := []net.IP{net.ParseIP("2001:db8::2")}
	if err := b.ApplyContainerRules(containerID, "nginx6", ips, sampleRuleSetIPv6(), "DROP", nil); err != nil {
		t.Fatalf("ApplyContainerRules: %v", err)
	}
	if err := b.RemoveContainerChains(containerID); err != nil {
		t.Fatalf("RemoveContainerChains: %v", err)
	}

	save := ip6tablesSave(t)
	assertNotContains(t, save, chain+"-abcdef012345")
	assertContains(t, save, ":"+chain+" - ")
}

func TestIP6Tables_OrphanRecovery_ReconcileRemovesChain(t *testing.T) {
	requireRoot(t)

	chain := testChainName(t)
	b := newIP6TablesBackend(t, chain)
	setupAndDefer(t, b)

	cid := "abcdef012345000000000000000000000000000000000000000000000000aaaa"
	if err := b.ApplyContainerRules(cid, "crashed6", []net.IP{net.ParseIP("2001:db8::5")}, sampleRuleSetIPv6(), "DROP", nil); err != nil {
		t.Fatalf("seed orphan chain: %v", err)
	}

	save := ip6tablesSave(t)
	assertContains(t, save, chain+"-abcdef012345")

	cfg := &config.Config{
		ChainName:      chain,
		EffectiveChain: chain,
		ParentChain:    "FORWARD",
		Backend:        "iptables",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	eng := rules.NewEngine(b, emptyDocker{}, cfg, logger)

	if err := eng.Rehydrate(context.Background()); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}
	if err := eng.Reconcile(context.Background(), audit.SourceStartup); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	save = ip6tablesSave(t)
	if strings.Contains(save, chain+"-abcdef012345") {
		t.Errorf("orphan IPv6 chain still present after Reconcile:\n%s", save)
	}
}
