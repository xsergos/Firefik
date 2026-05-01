package rules

import (
	"errors"
	"fmt"
	"strings"

	"firefik/internal/docker"
	"firefik/internal/geoip"
)

var ErrGeoIPUnavailable = errors.New("geoip database required but not configured")

type GeoIPApplyResult struct {
	Fatal    error
	Warnings []string
}

func applyGeoIP(rs *docker.FirewallRuleSet, db *geoip.DB) GeoIPApplyResult {
	hasGeoBlock := len(rs.GeoBlock) > 0
	hasGeoAllow := len(rs.GeoAllow) > 0

	if !hasGeoBlock && !hasGeoAllow {
		return GeoIPApplyResult{}
	}
	if db == nil {
		return GeoIPApplyResult{Fatal: ErrGeoIPUnavailable}
	}

	var res GeoIPApplyResult

	if hasGeoBlock {
		cidrs, err := db.CIDRsForCountries(rs.GeoBlock)
		if err != nil {
			res.Fatal = fmt.Errorf("geoblock lookup for %s: %w", strings.Join(rs.GeoBlock, ","), err)
			return res
		}
		if len(cidrs) == 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("geoblock %s: no matching networks in GeoIP DB", strings.Join(rs.GeoBlock, ",")))
		}
		rs.Blocklist = append(cidrs, rs.Blocklist...)
	}

	if hasGeoAllow {
		cidrs, err := db.CIDRsForCountries(rs.GeoAllow)
		if err != nil {
			res.Fatal = fmt.Errorf("geoallow lookup for %s: %w", strings.Join(rs.GeoAllow, ","), err)
			return res
		}
		if len(cidrs) == 0 {
			res.Fatal = fmt.Errorf("geoallow %s: no matching networks in GeoIP DB", strings.Join(rs.GeoAllow, ","))
			return res
		}
		rs.Allowlist = append(cidrs, rs.Allowlist...)
	}

	return res
}
