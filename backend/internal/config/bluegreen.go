package config

func DeriveLegacyChains(base, effective string, oldSuffixes []string) []string {
	if len(oldSuffixes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(oldSuffixes))
	out := make([]string, 0, len(oldSuffixes))
	for _, suf := range oldSuffixes {
		chain := base
		if suf != "" {
			chain = base + "-" + suf
		}
		if chain == effective {
			continue
		}
		if _, dup := seen[chain]; dup {
			continue
		}
		seen[chain] = struct{}{}
		out = append(out, chain)
	}
	return out
}
