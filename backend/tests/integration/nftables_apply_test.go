//go:build integration

package integration

import (
	"net"
	"strings"
	"testing"
)

func TestNFTables_SetupChains_CreatesTableAndForwardHook(t *testing.T) {
	requireRoot(t)
	chain := testChainName(t)
	b := newNFTablesBackend(t, chain)
	setupAndDefer(t, b)

	out := nftListRuleset(t)
	assertContains(t, out, "table inet firefik")
	assertContains(t, out, "chain forward")
}

func TestNFTables_ApplyContainerRules_CreatesContainerChain(t *testing.T) {
	requireRoot(t)
	chain := testChainName(t)
	b := newNFTablesBackend(t, chain)
	setupAndDefer(t, b)

	containerID := "abcdef012345000000000000000000000000000000000000000000000000aaaa"
	ips := []net.IP{net.ParseIP("10.244.0.2")}
	if err := b.ApplyContainerRules(containerID, "nginx", ips, sampleRuleSet(), "DROP", nil); err != nil {
		t.Fatalf("ApplyContainerRules: %v", err)
	}

	out := nftListRuleset(t)

	assertContains(t, out, strings.ToLower(chain)+"-abcdef012345")
	assertContains(t, out, "10.244.0.2")
}

func TestNFTables_Cleanup_ScopedByChainPrefix_BlueGreen(t *testing.T) {
	requireRoot(t)

	v1 := testChainName(t) + "V1"
	v2 := testChainName(t) + "V2"

	b1 := newNFTablesBackend(t, v1)
	b2 := newNFTablesBackend(t, v2)

	if err := b1.SetupChains(); err != nil {
		t.Fatalf("SetupChains v1: %v", err)
	}
	if err := b2.SetupChains(); err != nil {
		t.Fatalf("SetupChains v2: %v", err)
	}
	t.Cleanup(func() { _ = b2.Cleanup() })

	cid := "abcdef012345000000000000000000000000000000000000000000000000aaaa"
	if err := b1.ApplyContainerRules(cid, "app-v1", []net.IP{net.ParseIP("10.0.0.1")}, sampleRuleSet(), "DROP", nil); err != nil {
		t.Fatalf("apply v1: %v", err)
	}
	if err := b2.ApplyContainerRules(cid, "app-v2", []net.IP{net.ParseIP("10.0.0.2")}, sampleRuleSet(), "DROP", nil); err != nil {
		t.Fatalf("apply v2: %v", err)
	}

	if err := b1.Cleanup(); err != nil {
		t.Fatalf("b1.Cleanup: %v", err)
	}

	out := nftListRuleset(t)
	assertNotContains(t, out, strings.ToLower(v1)+"-abcdef012345")
	assertContains(t, out, strings.ToLower(v2)+"-abcdef012345")
	assertContains(t, out, "table inet firefik")
	assertContains(t, out, "chain forward")

	ids, err := b2.ListAppliedContainerIDs()
	if err != nil {
		t.Fatalf("b2.ListAppliedContainerIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != "abcdef012345" {
		t.Errorf("v2 should still see its own container, got %v", ids)
	}
}

func TestNFTables_Cleanup_DeletesTableWhenLastInstance(t *testing.T) {
	requireRoot(t)
	chain := testChainName(t)
	b := newNFTablesBackend(t, chain)
	if err := b.SetupChains(); err != nil {
		t.Fatalf("SetupChains: %v", err)
	}
	if err := b.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	out := nftListRuleset(t)
	if strings.Contains(out, "table inet firefik") {
		t.Errorf("firefik table should be removed when no other instance uses it:\n%s", out)
	}
}
