package docker

import (
	"net"
	"reflect"
	"testing"
)

func TestParseLabels_EnableFlag(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{"enable true", map[string]string{"firefik.enable": "true"}, true},
		{"enable false explicit", map[string]string{"firefik.enable": "false"}, false},
		{"enable 1 not accepted", map[string]string{"firefik.enable": "1"}, false},
		{"missing", map[string]string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, _ := ParseLabels(tt.labels)
			if cfg.Enable != tt.want {
				t.Fatalf("Enable = %v, want %v", cfg.Enable, tt.want)
			}
		})
	}
}

func TestParseLabels_DefaultPolicy(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantPolicy string
		wantErrs   int
	}{
		{"accept", "ACCEPT", "ACCEPT", 0},
		{"drop", "DROP", "DROP", 0},
		{"return", "RETURN", "RETURN", 0},
		{"lower is normalised", "drop", "DROP", 0},
		{"invalid is rejected", "NUKE", "", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, errs := ParseLabels(map[string]string{
				"firefik.defaultpolicy": tt.in,
			})
			if cfg.DefaultPolicy != tt.wantPolicy {
				t.Fatalf("DefaultPolicy = %q, want %q", cfg.DefaultPolicy, tt.wantPolicy)
			}
			if len(errs) != tt.wantErrs {
				t.Fatalf("errs = %d, want %d (%v)", len(errs), tt.wantErrs, errs)
			}
		})
	}
}

func TestParsePorts(t *testing.T) {
	cases := []struct {
		in      string
		want    []uint16
		wantErr bool
	}{
		{"80", []uint16{80}, false},
		{"80,443", []uint16{80, 443}, false},
		{" 80 , 443 ", []uint16{80, 443}, false},
		{"", nil, false},
		{"65535", []uint16{65535}, false},
		{"0", nil, true},
		{"70000", nil, true},
		{"abc", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parsePorts(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsNetworkName(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"my_network", true},
		{"app.prod", true},
		{"plain", true},
		{"192.168.1.1", false},
		{"192.168.1.0/24", false},
		{"192.168.1.1-10", false},
		{"::1", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := isNetworkName(tc.in); got != tc.want {
				t.Fatalf("isNetworkName(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseIPEntry_CIDR(t *testing.T) {
	got, err := parseIPEntry("10.0.0.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 net, got %d", len(got))
	}
	if got[0].String() != "10.0.0.0/24" {
		t.Fatalf("expected 10.0.0.0/24, got %s", got[0].String())
	}
}

func TestParseIPEntry_SingleIP(t *testing.T) {
	got, err := parseIPEntry("10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].String() != "10.0.0.1/32" {
		t.Fatalf("expected 10.0.0.1/32, got %+v", got)
	}
}

func TestParseRange_ShortSuffix(t *testing.T) {
	got, err := parseRange("192.168.1.10-20")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	total := 0
	for _, n := range got {
		ones, _ := n.Mask.Size()
		total += 1 << (32 - ones)
	}
	if total != 11 {
		t.Fatalf("expected range to cover 11 addresses, got %d (%v)", total, got)
	}
}

func TestParseRange_FullAddress(t *testing.T) {
	got, err := parseRange("10.0.0.1-10.0.0.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	total := 0
	for _, n := range got {
		ones, _ := n.Mask.Size()
		total += 1 << (32 - ones)
	}
	if total != 5 {
		t.Fatalf("expected 5 addresses, got %d (%v)", total, got)
	}
}

func TestParseRange_Inverted(t *testing.T) {
	if _, err := parseRange("10.0.0.5-10.0.0.1"); err == nil {
		t.Fatalf("expected error for inverted range")
	}
}

func TestParseIPListWithNetworks(t *testing.T) {
	cidrs, names, err := parseIPListWithNetworks("10.0.0.0/8, my_net, 192.168.1.5")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(cidrs) != 2 {
		t.Fatalf("expected 2 cidrs, got %d", len(cidrs))
	}
	if len(names) != 1 || names[0] != "my_net" {
		t.Fatalf("expected [my_net], got %v", names)
	}
	if !cidrs[0].Contains(net.ParseIP("10.42.0.1")) {
		t.Fatalf("cidr[0] should contain 10.42.0.1")
	}
}

func TestParseRuleSet_RateLimit(t *testing.T) {
	cfg, errs := ParseLabels(map[string]string{
		"firefik.enable":                       "true",
		"firefik.firewall.api.ports":           "443",
		"firefik.firewall.api.ratelimit.rate":  "100",
		"firefik.firewall.api.ratelimit.burst": "50",
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(cfg.RuleSets) != 1 {
		t.Fatalf("expected 1 rule set, got %d", len(cfg.RuleSets))
	}
	rs := cfg.RuleSets[0]
	if rs.RateLimit == nil {
		t.Fatalf("expected RateLimit to be set")
	}
	if rs.RateLimit.Rate != 100 || rs.RateLimit.Burst != 50 {
		t.Fatalf("got rate=%d burst=%d", rs.RateLimit.Rate, rs.RateLimit.Burst)
	}
}

func TestParseRuleSet_RateZeroIsRejected(t *testing.T) {
	cfg, errs := ParseLabels(map[string]string{
		"firefik.enable":                       "true",
		"firefik.firewall.api.ratelimit.rate":  "0",
		"firefik.firewall.api.ratelimit.burst": "10",
	})
	if len(errs) == 0 {
		t.Fatalf("expected rate=0 to be rejected")
	}
	if cfg.RuleSets[0].RateLimit != nil {
		t.Fatalf("RateLimit should have been dropped when rate=0")
	}
}

func TestSplitTrimmed(t *testing.T) {
	got := splitTrimmed(" a, b , ,c ,")
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseLabels_MissingParam(t *testing.T) {
	_, errs := ParseLabels(map[string]string{
		"firefik.firewall.": "",
	})
	if len(errs) == 0 {
		t.Fatalf("expected error for malformed label")
	}
}

func TestParseRange_BoundaryShortSuffix(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"single port byte", "10.0.0.5-5", false},
		{"max byte 255", "10.0.0.0-255", false},
		{"overflow short suffix", "10.0.0.0-256", true},
		{"non numeric short suffix", "10.0.0.0-abc", true},
		{"negative short suffix", "10.0.0.0--1", true},
		{"empty short suffix", "10.0.0.0-", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRange(tc.in)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q", tc.in)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
		})
	}
}

func TestParseRange_FullV4Boundary(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"single same address", "10.0.0.1-10.0.0.1", false},
		{"reversed range", "10.0.0.5-10.0.0.1", true},
		{"end is non-IPv4", "10.0.0.1-::1", true},
		{"invalid end", "10.0.0.1-not.an.ip.addr", true},
		{"empty start", "-10.0.0.1", true},
		{"only dash", "-", true},
		{"missing dash", "10.0.0.1", true},
		{"start invalid", "999.999.999.999-10.0.0.1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRange(tc.in)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q", tc.in)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.in, err)
			}
		})
	}
}

func TestParseRange_V6Basic(t *testing.T) {
	got, err := parseRange("::1-::2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Fatalf("expected at least one cidr")
	}
	for _, c := range got {
		if c.IP.To4() != nil {
			t.Fatalf("v6 range produced v4 net: %s", c.String())
		}
	}
}

func TestParseRange_V6Bigger(t *testing.T) {
	got, err := parseRange("2001:db8::1-2001:db8::ff")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Fatalf("expected cidrs")
	}
}

func TestParseRange_V6Single(t *testing.T) {
	got, err := parseRange("::1-::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 cidr, got %d", len(got))
	}
	ones, _ := got[0].Mask.Size()
	if ones != 128 {
		t.Fatalf("expected /128, got /%d", ones)
	}
}

func TestParseRange_V6Reversed(t *testing.T) {
	if _, err := parseRange("::ff-::1"); err == nil {
		t.Fatalf("expected error for reversed v6 range")
	}
}

func TestParseRange_V6CrossSlash16(t *testing.T) {
	got, err := parseRange("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff-2001:db8::5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Fatalf("expected cidrs across boundary")
	}
}

func TestParseRange_V6InvalidEnd(t *testing.T) {
	if _, err := parseRange("::1-not-an-ip"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseRange_V6EmptyEnd(t *testing.T) {
	if _, err := parseRange("::1-"); err == nil {
		t.Fatalf("expected error for empty v6 end")
	}
}

func TestRangeToCIDRsV6_Single(t *testing.T) {
	got, err := rangeToCIDRsV6(net.ParseIP("::1"), net.ParseIP("::1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 cidr, got %d", len(got))
	}
}

func TestRangeToCIDRsV6_Reversed(t *testing.T) {
	if _, err := rangeToCIDRsV6(net.ParseIP("::5"), net.ParseIP("::1")); err == nil {
		t.Fatalf("expected error")
	}
}

func TestRangeToCIDRsV6_Span(t *testing.T) {
	got, err := rangeToCIDRsV6(net.ParseIP("::1"), net.ParseIP("::ff"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	covered := 0
	for _, c := range got {
		ones, bits := c.Mask.Size()
		blockBits := uint(bits - ones)
		if blockBits > 30 {
			t.Fatalf("block too big in test")
		}
		covered += 1 << blockBits
	}
	if covered != 0xff {
		t.Fatalf("expected coverage 255, got %d", covered)
	}
}

func TestRangeToCIDRsV6_Overflow(t *testing.T) {
	got, err := rangeToCIDRsV6(net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"), net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Fatalf("expected at least one cidr near max")
	}
}

func TestRangeToCIDRsV6_CrossBoundary(t *testing.T) {
	got, err := rangeToCIDRsV6(net.ParseIP("2001:db7::ff"), net.ParseIP("2001:db8::1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Fatalf("expected cidrs across /16 boundary")
	}
}

func TestParseIPEntry_MalformedCIDR(t *testing.T) {
	cases := []string{
		"10.0.0.1/99",
		"10.0.0.1/abc",
		"::1/200",
		"/24",
		"/",
		"abc/24",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if _, err := parseIPEntry(c); err == nil {
				t.Fatalf("expected error for %q", c)
			}
		})
	}
}

func TestParseIPEntry_Empty(t *testing.T) {
	if _, err := parseIPEntry(""); err == nil {
		t.Fatalf("expected error for empty entry")
	}
}

func TestParseIPEntry_Unicode(t *testing.T) {
	if _, err := parseIPEntry("спец"); err == nil {
		t.Fatalf("expected error for unicode entry")
	}
}

func TestParseIPEntry_V6Shorthand(t *testing.T) {
	got, err := parseIPEntry("::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 net, got %d", len(got))
	}
	if got[0].String() != "::1/128" {
		t.Fatalf("expected ::1/128, got %s", got[0].String())
	}
}

func TestParseIPEntry_V6CIDR(t *testing.T) {
	got, err := parseIPEntry("2001:db8::/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].String() != "2001:db8::/32" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseIPEntry_V4Range(t *testing.T) {
	got, err := parseIPEntry("10.0.0.1-10.0.0.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Fatalf("expected at least one cidr")
	}
}
