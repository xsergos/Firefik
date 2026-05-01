//go:build linux

package rules

import "testing"

func TestParseInstanceChainName(t *testing.T) {
	cases := []struct {
		name   string
		chain  string
		prefix string
		wantID string
		wantRS bool
		wantOK bool
	}{
		{"main chain", "firefik-abcdef012345", "firefik-", "abcdef012345", false, true},
		{"rs sub chain", "firefik-abcdef012345-web", "firefik-", "abcdef012345", true, true},
		{"v2 main chain seen by v1 scanner", "firefik-v2-abcdef012345", "firefik-", "", false, false},
		{"v2 rs sub seen by v1 scanner", "firefik-v2-abcdef012345-web", "firefik-", "", false, false},
		{"short id too short", "firefik-abc", "firefik-", "", false, false},
		{"non-hex id", "firefik-zzzzzzzzzzzz", "firefik-", "", false, false},
		{"no prefix match", "docker-abcdef012345", "firefik-", "", false, false},
		{"prefix only", "firefik-", "firefik-", "", false, false},
		{"v2 scanner sees own chain", "firefik-v2-abcdef012345", "firefik-v2-", "abcdef012345", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotID, gotRS, gotOK := parseInstanceChainName(tc.chain, tc.prefix)
			if gotOK != tc.wantOK || gotID != tc.wantID || gotRS != tc.wantRS {
				t.Errorf("parseInstanceChainName(%q, %q) = (%q, %v, %v), want (%q, %v, %v)",
					tc.chain, tc.prefix, gotID, gotRS, gotOK, tc.wantID, tc.wantRS, tc.wantOK)
			}
		})
	}
}

func TestIsShortDockerID(t *testing.T) {
	cases := map[string]bool{
		"abcdef012345":  true,
		"000000000000":  true,
		"ABCDEF012345":  false,
		"abcdef01234":   false,
		"abcdef0123456": false,
		"abcdefghijkl":  false,
		"":              false,
	}
	for s, want := range cases {
		if got := isShortDockerID(s); got != want {
			t.Errorf("isShortDockerID(%q) = %v, want %v", s, got, want)
		}
	}
}
