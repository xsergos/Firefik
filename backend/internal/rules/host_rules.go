package rules

import (
	"net"
	"strings"
)

type HostRule struct {
	Name      string
	Protocol  string
	Ports     []uint16
	Allowlist []net.IPNet
	Blocklist []net.IPNet
	Log       bool
	LogPrefix string
}

func (r HostRule) protoNormalised() string {
	p := strings.ToLower(strings.TrimSpace(r.Protocol))
	switch p {
	case "", "any":
		return ""
	default:
		return p
	}
}

func NormaliseHostDefault(s string) string {
	v := strings.ToUpper(strings.TrimSpace(s))
	switch v {
	case "ACCEPT", "DROP":
		return v
	default:
		return "ACCEPT"
	}
}

const hostChainName = "FIREFIK_HOST"
