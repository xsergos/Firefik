package geoip

import (
	"fmt"
	"net"
	"strings"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

type countryRecord struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type DB struct {
	r *maxminddb.Reader
}

func Open(path string) (*DB, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open geoip db %q: %w", path, err)
	}
	return &DB{r: r}, nil
}

func (db *DB) Close() error {
	if db == nil || db.r == nil {
		return nil
	}
	return db.r.Close()
}

func (db *DB) CountryForIP(ip net.IP) string {
	if db == nil || db.r == nil {
		return ""
	}
	var rec countryRecord
	if err := db.r.Lookup(ip, &rec); err != nil {
		return ""
	}
	return rec.Country.IsoCode
}

func (db *DB) CIDRsForCountries(countries []string) ([]net.IPNet, error) {
	if db == nil || db.r == nil || len(countries) == 0 {
		return nil, nil
	}
	want := make(map[string]bool, len(countries))
	for _, c := range countries {
		want[strings.ToUpper(c)] = true
	}

	networks := db.r.Networks(maxminddb.SkipAliasedNetworks)
	var out []net.IPNet
	for networks.Next() {
		var rec countryRecord
		network, err := networks.Network(&rec)
		if err != nil {
			continue
		}
		if want[rec.Country.IsoCode] {
			out = append(out, *network)
		}
	}
	if err := networks.Err(); err != nil {
		return out, fmt.Errorf("geoip network iteration: %w", err)
	}
	return out, nil
}
