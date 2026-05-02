//go:build integration

package integration

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"

	"firefik/internal/audit"
	"firefik/internal/config"
	"firefik/internal/docker"
	"firefik/internal/rules"
)

type fakeDocker struct {
	mu         sync.Mutex
	containers []docker.ContainerInfo
}

func (f *fakeDocker) ListContainers(ctx context.Context) ([]docker.ContainerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]docker.ContainerInfo, len(f.containers))
	copy(out, f.containers)
	return out, nil
}

func (f *fakeDocker) Inspect(ctx context.Context, id string) (docker.ContainerInfo, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.containers {
		if c.ID == id || strings.HasPrefix(c.ID, id) {
			return c, true, nil
		}
	}
	return docker.ContainerInfo{}, false, nil
}

func (f *fakeDocker) set(cs []docker.ContainerInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.containers = cs
}

func makeContainer(id, name, ip string) docker.ContainerInfo {
	return docker.ContainerInfo{
		ID:     id,
		Name:   name,
		Status: "running",
		Labels: map[string]string{
			"firefik.enable":                 "true",
			"firefik.defaultpolicy":          "DROP",
			"firefik.firewall.web.ports":     "80,443",
			"firefik.firewall.web.allowlist": "10.0.0.0/8",
			"firefik.firewall.web.protocol":  "tcp",
		},
		Networks: map[string]docker.NetworkEndpoint{
			"bridge": {IP: ip, PrefixLen: 24},
		},
	}
}

func TestEngine_FullLifecycle_IPTables_ApplyReconcileRemove(t *testing.T) {
	requireRoot(t)

	chain := testChainName(t)
	b := newIPTablesBackend(t, chain)
	setupAndDefer(t, b)

	cid := "abcdef012345000000000000000000000000000000000000000000000000aaaa"
	dockerFake := &fakeDocker{}
	dockerFake.set([]docker.ContainerInfo{makeContainer(cid, "app", "10.0.0.10")})

	cfg := &config.Config{
		ChainName:      chain,
		EffectiveChain: chain,
		ParentChain:    "FORWARD",
		Backend:        "iptables",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	eng := rules.NewEngine(b, dockerFake, cfg, logger)
	if err := eng.Rehydrate(context.Background()); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	if err := eng.Reconcile(context.Background(), audit.SourceStartup); err != nil {
		t.Fatalf("Reconcile #1: %v", err)
	}
	save := iptablesSave(t)
	assertContains(t, save, chain+"-abcdef012345")
	assertContains(t, save, "10.0.0.10")
	assertContains(t, save, "--dport 80")
	assertContains(t, save, "--dport 443")

	if err := eng.Reconcile(context.Background(), audit.SourceConfigReload); err != nil {
		t.Fatalf("Reconcile #2 (idempotent): %v", err)
	}
	save = iptablesSave(t)
	assertContains(t, save, chain+"-abcdef012345")

	dockerFake.set(nil)
	if err := eng.Reconcile(context.Background(), audit.SourceConfigReload); err != nil {
		t.Fatalf("Reconcile #3 (drift): %v", err)
	}
	save = iptablesSave(t)
	if strings.Contains(save, chain+"-abcdef012345") {
		t.Errorf("container chain should be removed when container disappears:\n%s", save)
	}
}

func TestEngine_BlueGreen_PreservesV2WhenV1Cleans(t *testing.T) {
	requireRoot(t)

	v1 := testChainName(t) + "1"
	v2 := testChainName(t) + "2"
	if len(v1) > 8 {
		v1 = v1[:8]
	}
	if len(v2) > 8 {
		v2 = v2[:8]
	}

	bv1 := newIPTablesBackend(t, v1)
	bv2 := newIPTablesBackend(t, v2)

	if err := bv1.SetupChains(); err != nil {
		t.Fatalf("SetupChains v1: %v", err)
	}
	if err := bv2.SetupChains(); err != nil {
		t.Fatalf("SetupChains v2: %v", err)
	}
	t.Cleanup(func() {
		_ = bv2.Cleanup()
	})

	cid := "abcdef012345000000000000000000000000000000000000000000000000aaaa"
	dockerFake := &fakeDocker{}
	dockerFake.set([]docker.ContainerInfo{makeContainer(cid, "app", "10.0.0.20")})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfgV1 := &config.Config{ChainName: v1, EffectiveChain: v1, ParentChain: "FORWARD", Backend: "iptables"}
	cfgV2 := &config.Config{ChainName: v2, EffectiveChain: v2, ParentChain: "FORWARD", Backend: "iptables"}

	engV1 := rules.NewEngine(bv1, dockerFake, cfgV1, logger)
	engV2 := rules.NewEngine(bv2, dockerFake, cfgV2, logger)
	if err := engV1.Rehydrate(context.Background()); err != nil {
		t.Fatalf("Rehydrate v1: %v", err)
	}
	if err := engV2.Rehydrate(context.Background()); err != nil {
		t.Fatalf("Rehydrate v2: %v", err)
	}
	if err := engV1.Reconcile(context.Background(), audit.SourceStartup); err != nil {
		t.Fatalf("v1 Reconcile: %v", err)
	}
	if err := engV2.Reconcile(context.Background(), audit.SourceStartup); err != nil {
		t.Fatalf("v2 Reconcile: %v", err)
	}

	save := iptablesSave(t)
	assertContains(t, save, v1+"-abcdef012345")
	assertContains(t, save, v2+"-abcdef012345")

	v1IDs, err := bv1.ListAppliedContainerIDs()
	if err != nil {
		t.Fatalf("v1 ListAppliedContainerIDs: %v", err)
	}
	for _, id := range v1IDs {
		if err := bv1.RemoveContainerChains(id); err != nil {
			t.Fatalf("v1 RemoveContainerChains(%s): %v", id, err)
		}
	}
	if err := bv1.Cleanup(); err != nil {
		t.Fatalf("v1 Cleanup: %v", err)
	}

	save = iptablesSave(t)
	if strings.Contains(save, v1+"-abcdef012345") {
		t.Errorf("v1 chain leaked after drain+Cleanup:\n%s", save)
	}
	assertContains(t, save, v2+"-abcdef012345")
}

func TestEngine_FullLifecycle_NFTables_ApplyAndRemove(t *testing.T) {
	requireRoot(t)

	chain := testChainName(t)
	b := newNFTablesBackend(t, chain)
	setupAndDefer(t, b)

	cid := "abcdef012345000000000000000000000000000000000000000000000000aaaa"
	dockerFake := &fakeDocker{}
	dockerFake.set([]docker.ContainerInfo{makeContainer(cid, "app", "10.0.0.30")})

	cfg := &config.Config{
		ChainName:      chain,
		EffectiveChain: chain,
		ParentChain:    "FORWARD",
		Backend:        "nftables",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	eng := rules.NewEngine(b, dockerFake, cfg, logger)
	eng.SetInetBackend(true)
	if err := eng.Rehydrate(context.Background()); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	if err := eng.Reconcile(context.Background(), audit.SourceStartup); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	out := nftListRuleset(t)
	lowered := strings.ToLower(chain) + "-abcdef012345"
	assertContains(t, out, lowered)
	assertContains(t, out, "10.0.0.30")

	dockerFake.set(nil)
	if err := eng.Reconcile(context.Background(), audit.SourceConfigReload); err != nil {
		t.Fatalf("Reconcile drift: %v", err)
	}
	out = nftListRuleset(t)
	if strings.Contains(out, lowered) {
		t.Errorf("nftables chain should be removed when container disappears:\n%s", out)
	}
}
