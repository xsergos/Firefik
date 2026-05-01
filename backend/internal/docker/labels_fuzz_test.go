package docker

import (
	"strings"
	"testing"
)

func FuzzParseLabels(f *testing.F) {
	seeds := []map[string]string{
		{},
		{"firefik.enable": "true"},
		{"firefik.enable": "true", "firefik.defaultpolicy": "DROP"},
		{"firefik.firewall.web.ports": "80,443", "firefik.firewall.web.protocol": "tcp"},
		{"firefik.firewall.web.ports": "80", "firefik.firewall.web.allowlist": "10.0.0.0/8,192.168.0.0/16"},
		{"firefik.firewall.rl.ports": "22", "firefik.firewall.rl.ratelimit": "100/s", "firefik.firewall.rl.protocol": "tcp"},
		{"firefik.firewall.bad.ports": "notaport"},
		{"firefik.firewall.weird..ports": "80"},
		{"firefik.firewall.geo.ports": "443", "firefik.firewall.geo.geoblock": "RU,CN"},
	}
	for _, s := range seeds {
		key, val := "", ""
		for k, v := range s {
			key = k
			val = v
			break
		}
		f.Add(key, val)
	}

	extra := []struct{ k, v string }{
		{"", ""},
		{"firefik.firewall.web.allowlist", "192.168.1.0/24"},
		{"firefik.firewall.web.allowlist", "::1/128"},
		{"firefik.firewall.web.allowlist", "2001:db8::/32"},
		{"firefik.firewall.web.allowlist", "10.0.0.0/99"},
		{"firefik.firewall.web.allowlist", "999.999.999.999"},
		{"firefik.firewall.web.allowlist", "::g"},
		{"firefik.firewall.web.ports", "80;"},
		{"firefik.firewall.web.ports", "80;;;"},
		{"firefik.firewall.web.ports", "1-99999999"},
		{"firefik.firewall.web.ports", "65535"},
		{"firefik.firewall.web.ports", "65536"},
		{"firefik.firewall.web.ports", "0"},
		{"firefik.firewall.web.ports", "-1"},
		{"firefik.firewall.unicode.ports", "восемьдесят"},
		{"firefik.firewall.web.ratelimit.rate", "abc"},
		{"firefik.firewall.web.ratelimit.burst", "abc"},
		{"firefik.firewall.web.ratelimit.rate", "0"},
		{"firefik.firewall.web.ratelimit.burst", "0"},
		{"firefik.firewall.web.geoblock", "RU,CN,US"},
		{"firefik.firewall.web.geoallow", ""},
		{"firefik.firewall.web.schedule", "garbage"},
		{"firefik.firewall.web.log", "true"},
		{"firefik.firewall.web.log.prefix", "[fw] "},
		{"firefik.firewall.web.protocol", "tcp"},
		{"firefik.firewall.web.profile", "strict"},
		{"firefik.firewall.web.allowlist", "10.0.0.1-10.0.0.50"},
		{"firefik.firewall.web.allowlist", "10.0.0.50-10.0.0.1"},
		{"firefik.firewall.web.allowlist", "::1-::ff"},
		{"firefik.firewall.web.allowlist", "::ff-::1"},
		{"firefik.firewall.web.ports", "80;DROP;echo pwn"},
		{"firefik.firewall.web.ports", "bad;;;"},
		{"firefik.firewall.web.allowlist", "my_network,10.0.0.0/8"},
		{"firefik.firewall.\x00null.ports", "80"},
		{"firefik.firewall.web.ports", "80\x00443"},
		{"firefik.firewall.web.allowlist", strings.Repeat("10.0.0.0/8,", 256)},
		{"firefik.enable", "TRUE"},
		{"firefik.no-auto-allowlist", "true"},
		{"firefik.defaultpolicy", "INVALID"},
		{"firefik.firewall.", ""},
		{"firefik.firewall", ""},
		{"firefik.firewall.web.", ""},
		{"firefik.firewall.x.allowlist", "/"},
		{"firefik.firewall.x.allowlist", "/24"},
	}
	for _, p := range extra {
		f.Add(p.k, p.v)
	}

	f.Fuzz(func(t *testing.T, key, val string) {

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseLabels panicked on key=%q val=%q: %v", key, val, r)
			}
		}()
		_, _ = ParseLabels(map[string]string{key: val})
	})
}
