//go:build linux

package rules

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
)

func NewIP6TablesBackend(chainName, parentChain string) (*IPTablesBackend, error) {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return nil, fmt.Errorf("init ip6tables: %w", err)
	}
	return &IPTablesBackend{
		ipt:         ipt,
		chainName:   chainName,
		parentChain: parentChain,
	}, nil
}
