package rules

import (
	"fmt"
	"net"
	"strings"

	"firefik/internal/config"
)

func (e *Engine) applyHostRules(rf config.RulesFile) error {
	if e.backend == nil {
		return nil
	}
	if len(rf.HostRules) == 0 && strings.TrimSpace(rf.HostDefault) == "" {
		_ = e.backend.RemoveHostChain()
		if e.ip6backend != nil {
			_ = e.ip6backend.RemoveHostChain()
		}
		return nil
	}

	rules, parseErrs := convertHostRules(rf.HostRules)
	for _, perr := range parseErrs {
		e.logger.Warn("host rule parse", "error", perr)
	}

	defaultPolicy := NormaliseHostDefault(rf.HostDefault)
	if err := e.backend.ApplyHostRules(rules, defaultPolicy); err != nil {
		return fmt.Errorf("apply host rules: %w", err)
	}
	if e.ip6backend != nil {
		if err := e.ip6backend.ApplyHostRules(rules, defaultPolicy); err != nil {
			return fmt.Errorf("apply host rules (ipv6): %w", err)
		}
	}
	return nil
}

func convertHostRules(fileRules []config.FileHostRuleSet) ([]HostRule, []error) {
	out := make([]HostRule, 0, len(fileRules))
	var errs []error
	for _, fr := range fileRules {
		name := strings.TrimSpace(fr.Name)
		if name == "" {
			errs = append(errs, fmt.Errorf("host rule without name skipped"))
			continue
		}
		allowNets, allowErrs := parseCIDRList(fr.Allowlist)
		for _, e := range allowErrs {
			errs = append(errs, fmt.Errorf("host rule %q allowlist: %w", name, e))
		}
		blockNets, blockErrs := parseCIDRList(fr.Blocklist)
		for _, e := range blockErrs {
			errs = append(errs, fmt.Errorf("host rule %q blocklist: %w", name, e))
		}
		out = append(out, HostRule{
			Name:      name,
			Protocol:  strings.ToLower(strings.TrimSpace(fr.Protocol)),
			Ports:     append([]uint16(nil), fr.Ports...),
			Allowlist: allowNets,
			Blocklist: blockNets,
		})
	}
	return out, errs
}

func parseCIDRList(entries []string) ([]net.IPNet, []error) {
	var nets []net.IPNet
	var errs []error
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			if strings.Contains(e, ":") {
				e += "/128"
			} else {
				e += "/32"
			}
		}
		_, ipNet, err := net.ParseCIDR(e)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid CIDR %q: %w", e, err))
			continue
		}
		nets = append(nets, *ipNet)
	}
	return nets, errs
}
