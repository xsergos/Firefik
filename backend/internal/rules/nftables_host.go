//go:build linux

package rules

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const nftHostChainName = "firefik_host"

func (b *NFTablesBackend) ApplyHostRules(rules []HostRule, defaultPolicy string) error {
	if b.table == nil {
		if err := b.SetupChains(); err != nil {
			return fmt.Errorf("ensure table: %w", err)
		}
	}

	chain, err := b.ensureHostChain(defaultPolicy)
	if err != nil {
		return err
	}

	if err := b.flushHostChainRules(chain); err != nil {
		return fmt.Errorf("flush host chain: %w", err)
	}

	if b.stateful {
		b.conn.AddRule(&nftables.Rule{
			Table: b.table,
			Chain: chain,
			Exprs: ctStateEstablishedRelatedAcceptExprs(),
		})
	}

	for _, rule := range rules {
		proto := strings.ToLower(strings.TrimSpace(rule.Protocol))
		for _, peer := range rule.Blocklist {
			if err := b.addHostMatch(chain, proto, rule.Ports, peer, expr.VerdictDrop); err != nil {
				return fmt.Errorf("host rule %q blocklist %s: %w", rule.Name, peer.String(), err)
			}
		}
		for _, peer := range rule.Allowlist {
			if err := b.addHostMatch(chain, proto, rule.Ports, peer, expr.VerdictAccept); err != nil {
				return fmt.Errorf("host rule %q allowlist %s: %w", rule.Name, peer.String(), err)
			}
		}
		if len(rule.Allowlist) == 0 && len(rule.Blocklist) == 0 {
			if err := b.addHostMatch(chain, proto, rule.Ports, net.IPNet{}, expr.VerdictAccept); err != nil {
				return fmt.Errorf("host rule %q bare allow: %w", rule.Name, err)
			}
		}
	}

	return b.conn.Flush()
}

func (b *NFTablesBackend) RemoveHostChain() error {
	if b.table == nil {
		return nil
	}
	chains, err := b.conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("list chains: %w", err)
	}
	for _, ch := range chains {
		if ch.Table != nil && ch.Table.Name == nftTableName && ch.Name == nftHostChainName {
			b.conn.DelChain(ch)
			return b.conn.Flush()
		}
	}
	return nil
}

func (b *NFTablesBackend) ensureHostChain(defaultPolicy string) (*nftables.Chain, error) {
	existing, err := b.conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil, fmt.Errorf("list chains: %w", err)
	}
	policy := nftables.ChainPolicyAccept
	if NormaliseHostDefault(defaultPolicy) == "DROP" {
		policy = nftables.ChainPolicyDrop
	}
	for _, ch := range existing {
		if ch.Table != nil && ch.Table.Name == nftTableName && ch.Name == nftHostChainName {
			if ch.Policy == nil || *ch.Policy != policy {
				b.conn.DelChain(ch)
				if err := b.conn.Flush(); err != nil {
					return nil, fmt.Errorf("delete stale host chain: %w", err)
				}
				break
			}
			return ch, nil
		}
	}

	prio := nftables.ChainPriorityFilter
	chain := b.conn.AddChain(&nftables.Chain{
		Name:     nftHostChainName,
		Table:    b.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: prio,
		Policy:   &policy,
	})
	if err := b.conn.Flush(); err != nil {
		return nil, fmt.Errorf("create host chain: %w", err)
	}
	return chain, nil
}

func (b *NFTablesBackend) flushHostChainRules(chain *nftables.Chain) error {
	rules, err := b.conn.GetRules(b.table, chain)
	if err != nil {
		return err
	}
	for _, r := range rules {
		b.conn.DelRule(r)
	}
	return b.conn.Flush()
}

func (b *NFTablesBackend) addHostMatch(
	chain *nftables.Chain,
	proto string,
	ports []uint16,
	peer net.IPNet,
	verdict expr.VerdictKind,
) error {
	exprs := make([]expr.Any, 0, 8)
	if peer.IP != nil {
		exprs = append(exprs, srcNetMatchExprs(peer)...)
	}
	if proto == "tcp" || proto == "udp" {
		if len(ports) == 0 {
			exprs = append(exprs, protoAnyPortExprs(proto)...)
			exprs = append(exprs, &expr.Verdict{Kind: verdict})
			b.conn.AddRule(&nftables.Rule{Table: b.table, Chain: chain, Exprs: exprs})
			return nil
		}
		for _, port := range ports {
			ruleExprs := make([]expr.Any, 0, 12)
			ruleExprs = append(ruleExprs, exprs...)
			ruleExprs = append(ruleExprs, protoPortExprs(proto, port)...)
			ruleExprs = append(ruleExprs, &expr.Verdict{Kind: verdict})
			b.conn.AddRule(&nftables.Rule{Table: b.table, Chain: chain, Exprs: ruleExprs})
		}
		return nil
	}
	exprs = append(exprs, &expr.Verdict{Kind: verdict})
	b.conn.AddRule(&nftables.Rule{Table: b.table, Chain: chain, Exprs: exprs})
	return nil
}

func protoAnyPortExprs(proto string) []expr.Any {
	var protoNum uint8
	if strings.ToLower(proto) == "udp" {
		protoNum = 17
	} else {
		protoNum = 6
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoNum}},
	}
}
