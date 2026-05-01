//go:build linux

package rules

import (
	"strings"
	"testing"
)

func TestContainerChainName_BoundsGuard(t *testing.T) {
	b := &IPTablesBackend{chainName: "FIREFIK"}
	cases := []string{"abc", "ab", "", "0123456789abcdef"}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on id=%q: %v", id, r)
				}
			}()
			name := b.containerChainName(id)
			if !strings.HasPrefix(name, "FIREFIK-") && name != "FIREFIK-" {
				t.Fatalf("expected FIREFIK- prefix, got %q", name)
			}
		})
	}
}

func TestRuleJumpsTo(t *testing.T) {
	targetA := "FIREFIK-abc12345"
	targetB := "FIREFIK-abc123456"

	parts := strings.Fields("-A FIREFIK -d 172.17.0.2/32 -j FIREFIK-abc12345")
	if !ruleJumpsTo(parts, targetA) {
		t.Fatalf("expected ruleJumpsTo to match exact chain")
	}
	if ruleJumpsTo(parts, targetB) {
		t.Fatalf("ruleJumpsTo must not match a longer chain by substring (collision risk)")
	}
}

func TestRuleSetChainName_Truncation(t *testing.T) {
	b := &IPTablesBackend{chainName: "FIREFIK"}
	long := strings.Repeat("x", 40)
	got := b.ruleSetChainName("abcdef123456", long)
	if len(got) > iptablesMaxChainLen {
		t.Fatalf("chain name %q exceeds iptables max length (%d)", got, iptablesMaxChainLen)
	}
	if !strings.HasPrefix(got, "FIREFIK-abcdef123456-") {
		t.Fatalf("expected chain prefix, got %q", got)
	}
}
