//go:build integration

package integration

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"firefik/internal/docker"
	"firefik/internal/rules"
)

var chainCounter atomic.Int64

func testChainName(t *testing.T) string {
	t.Helper()
	n := chainCounter.Add(1)
	name := fmt.Sprintf("FFK%d%d", time.Now().UnixNano()%100_000, n)
	if len(name) > 8 {
		name = name[:8]
	}
	return name
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration test requires root (CAP_NET_ADMIN); run with sudo -E go test -tags=integration ./tests/integration/...")
	}
}

func iptablesSave(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "iptables-save", "-t", "filter").Output()
	if err != nil {
		t.Fatalf("iptables-save failed: %v", err)
	}
	return string(out)
}

func nftListRuleset(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "nft", "list", "ruleset").Output()
	if err != nil {
		t.Fatalf("nft list ruleset failed: %v", err)
	}
	return string(out)
}

func newIPTablesBackend(t *testing.T, chain string) rules.Backend {
	t.Helper()
	b, err := rules.NewIPTablesBackend(chain, "FORWARD")
	if err != nil {
		t.Fatalf("NewIPTablesBackend(%s): %v", chain, err)
	}
	return b
}

func newNFTablesBackend(t *testing.T, chain string) rules.Backend {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	b, err := rules.NewNFTablesBackend(chain, logger)
	if err != nil {
		t.Fatalf("NewNFTablesBackend(%s): %v", chain, err)
	}
	return b
}

func setupAndDefer(t *testing.T, b rules.Backend) {
	t.Helper()
	if err := b.SetupChains(); err != nil {
		t.Fatalf("SetupChains: %v", err)
	}
	t.Cleanup(func() {
		if err := b.Cleanup(); err != nil {
			t.Logf("cleanup warning: %v", err)
		}
	})
}

func sampleRuleSet() []docker.FirewallRuleSet {
	return []docker.FirewallRuleSet{
		{
			Name:      "web",
			Ports:     []uint16{80, 443},
			Protocol:  "tcp",
			Allowlist: []net.IPNet{mustCIDR("10.0.0.0/8")},
		},
	}
}

func mustCIDR(s string) net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *n
}

func assertContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected to find %q in output, got:\n%s", needle, haystack)
	}
}

func assertNotContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Errorf("expected NOT to find %q in output, got:\n%s", needle, haystack)
	}
}
