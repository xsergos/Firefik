package rules

import (
	"net"
	"testing"

	"firefik/internal/config"
	"firefik/internal/docker"
)

func TestApplyProfileWeb(t *testing.T) {
	rs := &docker.FirewallRuleSet{Profile: "web"}
	applyProfile(rs)
	if len(rs.Ports) != 2 || rs.Ports[0] != 80 || rs.Ports[1] != 443 {
		t.Errorf("ports = %v", rs.Ports)
	}
	if len(rs.Allowlist) != 2 {
		t.Errorf("allowlist len = %d", len(rs.Allowlist))
	}
}

func TestApplyProfileWebPreservesUserPorts(t *testing.T) {
	rs := &docker.FirewallRuleSet{Profile: "web", Ports: []uint16{8080}}
	applyProfile(rs)
	if len(rs.Ports) != 1 || rs.Ports[0] != 8080 {
		t.Errorf("user ports overridden: %v", rs.Ports)
	}
}

func TestApplyProfileInternal(t *testing.T) {
	rs := &docker.FirewallRuleSet{Profile: "internal"}
	applyProfile(rs)
	if len(rs.Allowlist) != 4 {
		t.Errorf("allowlist len = %d", len(rs.Allowlist))
	}
}

func TestApplyProfileInternalPreservesUserAllowlist(t *testing.T) {
	_, n, _ := net.ParseCIDR("8.8.8.0/24")
	rs := &docker.FirewallRuleSet{Profile: "internal", Allowlist: []net.IPNet{*n}}
	applyProfile(rs)
	if len(rs.Allowlist) != 1 {
		t.Errorf("user allowlist overridden: %v", rs.Allowlist)
	}
}

func TestApplyProfileUnknown(t *testing.T) {
	rs := &docker.FirewallRuleSet{Profile: "voodoo"}
	applyProfile(rs)
}

func TestParseCIDRLenientEmpty(t *testing.T) {
	if got := parseCIDRLenient(""); got != nil {
		t.Errorf("got %v", got)
	}
}

func TestParseCIDRLenientHostV4(t *testing.T) {
	if got := parseCIDRLenient("1.2.3.4"); got == nil || got.String() != "1.2.3.4/32" {
		t.Errorf("got %v", got)
	}
}

func TestParseCIDRLenientHostV6(t *testing.T) {
	if got := parseCIDRLenient("2001:db8::1"); got == nil || got.String() != "2001:db8::1/128" {
		t.Errorf("got %v", got)
	}
}

func TestParseCIDRLenientCIDR(t *testing.T) {
	if got := parseCIDRLenient("10.0.0.0/8"); got == nil || got.String() != "10.0.0.0/8" {
		t.Errorf("got %v", got)
	}
}

func TestParseCIDRLenientInvalid(t *testing.T) {
	if got := parseCIDRLenient("not-a-cidr"); got != nil {
		t.Errorf("got %v", got)
	}
}

func TestParseRatelimitEmpty(t *testing.T) {
	if got := parseRatelimitLenient(""); got != nil {
		t.Errorf("got %v", got)
	}
}

func TestParseRatelimitSimple(t *testing.T) {
	got := parseRatelimitLenient("100/s")
	if got == nil || got.Rate != 100 || got.Burst != 200 {
		t.Errorf("got %+v", got)
	}
}

func TestParseRatelimitWithBurst(t *testing.T) {
	got := parseRatelimitLenient("50/s, burst=300")
	if got == nil || got.Rate != 50 || got.Burst != 300 {
		t.Errorf("got %+v", got)
	}
}

func TestParseRatelimitInvalid(t *testing.T) {
	if got := parseRatelimitLenient("not-a-number"); got != nil {
		t.Errorf("got %v", got)
	}
}

func TestTemplateToRuleSetFull(t *testing.T) {
	tpl := config.RuleTemplate{
		Name:              "web",
		Version:           "v1",
		Ports:             []uint16{80, 443},
		Protocol:          "tcp",
		Profile:           "web",
		Log:               true,
		LogPrefix:         "FW:",
		AllowlistNetworks: []string{"net1"},
		BlocklistNetworks: []string{"net2"},
		GeoBlock:          []string{"KP"},
		GeoAllow:          []string{"RU"},
		Allowlist:         []string{"10.0.0.0/8", "1.2.3.4"},
		Blocklist:         []string{"5.6.7.8"},
		Ratelimit:         "100/s",
	}
	rs := templateToRuleSet(tpl)
	if rs.Name != "tpl:web@v1" {
		t.Errorf("name = %q", rs.Name)
	}
	if len(rs.Ports) != 2 || len(rs.Allowlist) != 2 || len(rs.Blocklist) != 1 {
		t.Errorf("rs = %+v", rs)
	}
	if rs.RateLimit == nil {
		t.Errorf("ratelimit nil")
	}
}

func TestTemplateToRuleSetSkipsBadCIDRs(t *testing.T) {
	tpl := config.RuleTemplate{
		Name:      "x",
		Version:   "v1",
		Allowlist: []string{"not-a-cidr", "10.0.0.0/8"},
		Blocklist: []string{"also-bad"},
	}
	rs := templateToRuleSet(tpl)
	if len(rs.Allowlist) != 1 {
		t.Errorf("expected 1 allow, got %d", len(rs.Allowlist))
	}
	if len(rs.Blocklist) != 0 {
		t.Errorf("expected 0 block, got %d", len(rs.Blocklist))
	}
}

func TestSplitCommaPolicyDedupes(t *testing.T) {
	got := splitCommaPolicy("a, b, a, c, ,b")
	if len(got) != 3 {
		t.Errorf("got %v", got)
	}
}

func TestSplitCommaPolicyEmpty(t *testing.T) {
	if got := splitCommaPolicy(""); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}
