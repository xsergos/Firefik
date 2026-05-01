//go:build integration

package integration

import (
	"context"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"

	"firefik/internal/audit"
	"firefik/internal/config"
	"firefik/internal/docker"
	"firefik/internal/rules"
)

type emptyDocker struct{}

func (emptyDocker) ListContainers(ctx context.Context) ([]docker.ContainerInfo, error) {
	return nil, nil
}

func (emptyDocker) Inspect(ctx context.Context, id string) (docker.ContainerInfo, bool, error) {
	return docker.ContainerInfo{}, false, nil
}

func TestOrphanRecovery_IPTables_ReconcileRemovesChainFromDeadRun(t *testing.T) {
	requireRoot(t)

	chain := testChainName(t)
	b := newIPTablesBackend(t, chain)
	setupAndDefer(t, b)

	cid := "abcdef012345000000000000000000000000000000000000000000000000aaaa"
	if err := b.ApplyContainerRules(cid, "crashed", []net.IP{net.ParseIP("10.0.0.5")}, sampleRuleSet(), "DROP", nil); err != nil {
		t.Fatalf("seed orphan chain: %v", err)
	}

	save := iptablesSave(t)
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

	save = iptablesSave(t)
	if strings.Contains(save, chain+"-abcdef012345") {
		t.Errorf("orphan chain still present after Reconcile:\n%s", save)
	}
}

func TestOrphanRecovery_NFTables_ReconcileRemovesChainFromDeadRun(t *testing.T) {
	requireRoot(t)

	chain := testChainName(t)
	b := newNFTablesBackend(t, chain)
	setupAndDefer(t, b)

	cid := "abcdef012345000000000000000000000000000000000000000000000000aaaa"
	if err := b.ApplyContainerRules(cid, "crashed", []net.IP{net.ParseIP("10.0.0.5")}, sampleRuleSet(), "DROP", nil); err != nil {
		t.Fatalf("seed orphan chain: %v", err)
	}

	lowered := strings.ToLower(chain) + "-abcdef012345"
	out := nftListRuleset(t)
	assertContains(t, out, lowered)

	cfg := &config.Config{
		ChainName:      chain,
		EffectiveChain: chain,
		ParentChain:    "FORWARD",
		Backend:        "nftables",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	eng := rules.NewEngine(b, emptyDocker{}, cfg, logger)
	eng.SetInetBackend(true)

	if err := eng.Rehydrate(context.Background()); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}
	if err := eng.Reconcile(context.Background(), audit.SourceStartup); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	out = nftListRuleset(t)
	if strings.Contains(out, lowered) {
		t.Errorf("orphan nftables chain still present after Reconcile:\n%s", out)
	}
}
