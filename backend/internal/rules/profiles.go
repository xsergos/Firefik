package rules

import (
	"net"

	"firefik/internal/docker"
)

func applyProfile(rs *docker.FirewallRuleSet) {
	switch rs.Profile {
	case "web":
		if len(rs.Ports) == 0 {
			rs.Ports = []uint16{80, 443}
		}
		if len(rs.Allowlist) == 0 {
			_, all4, _ := net.ParseCIDR("0.0.0.0/0")
			_, all6, _ := net.ParseCIDR("::/0")
			rs.Allowlist = []net.IPNet{*all4, *all6}
		}

	case "internal":
		if len(rs.Allowlist) == 0 {
			var private []net.IPNet
			for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
				_, n, _ := net.ParseCIDR(cidr)
				private = append(private, *n)
			}
			rs.Allowlist = private
		}
	}
}
