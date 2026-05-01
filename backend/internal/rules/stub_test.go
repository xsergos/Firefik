//go:build !linux

package rules

import (
	"net"
	"testing"

	"firefik/internal/docker"
)

func TestIPTablesStubReturnsErr(t *testing.T) {
	if _, err := NewIPTablesBackend("F", "P"); err == nil {
		t.Errorf("expected error on non-linux")
	}
	if _, err := NewIP6TablesBackend("F", "P"); err == nil {
		t.Errorf("expected error on non-linux")
	}
}

func TestIPTablesStubMethods(t *testing.T) {
	b := &IPTablesBackend{}
	if err := b.SetupChains(); err != nil {
		t.Errorf("setup err: %v", err)
	}
	if err := b.Cleanup(); err != nil {
		t.Errorf("cleanup err: %v", err)
	}
	b.SetStateful(true)
	if err := b.ApplyContainerRules("c", "n", []net.IP{}, []docker.FirewallRuleSet{}, "deny", nil); err != nil {
		t.Errorf("apply err: %v", err)
	}
	if err := b.RemoveContainerChains("c"); err != nil {
		t.Errorf("remove err: %v", err)
	}
	ids, err := b.ListAppliedContainerIDs()
	if err != nil || ids != nil {
		t.Errorf("list err=%v ids=%v", err, ids)
	}
	rep, err := b.Healthy()
	if err != nil {
		t.Errorf("healthy err: %v", err)
	}
	if rep.Backend != "iptables" {
		t.Errorf("backend=%q", rep.Backend)
	}
}

func TestNFTablesStubReturnsErr(t *testing.T) {
	if _, err := NewNFTablesBackend("F", nil); err == nil {
		t.Errorf("expected error on non-linux")
	}
}

func TestNFTablesStubMethods(t *testing.T) {
	b := &NFTablesBackend{}
	if err := b.SetupChains(); err != nil {
		t.Errorf("setup err: %v", err)
	}
	if err := b.Cleanup(); err != nil {
		t.Errorf("cleanup err: %v", err)
	}
	b.SetStateful(false)
	if err := b.ApplyContainerRules("c", "n", []net.IP{}, []docker.FirewallRuleSet{}, "allow", nil); err != nil {
		t.Errorf("apply err: %v", err)
	}
	if err := b.RemoveContainerChains("c"); err != nil {
		t.Errorf("remove err: %v", err)
	}
	if _, err := b.ListAppliedContainerIDs(); err != nil {
		t.Errorf("list err: %v", err)
	}
	if _, err := b.Healthy(); err != nil {
		t.Errorf("healthy err: %v", err)
	}
}

func TestDetectBackendType(t *testing.T) {
	if got := DetectBackendType(); got != "iptables" {
		t.Errorf("got %q", got)
	}
}
