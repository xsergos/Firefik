package config

import (
	"strings"
	"testing"
)

func FuzzValidateSuffix(f *testing.F) {
	seeds := []string{
		"v1",
		"v2-green",
		"A_B-c0",
		"",
		"bad suffix",
		"спец",
		"x/y",
		"x\x00y",
		"v2",
		strings.Repeat("a", 1024),
		"-bad",
		"line\nfeed",
		"tab\there",
		"\x01\x02\x03",
		strings.Repeat("z", 10240),
		"FIREFIK",
		"v2'; DROP TABLE",
		"../etc/passwd",
		"--",
		"_",
		"0",
		"v1.0",
		"v1+v2",
		" leading",
		"trailing ",
		"\r\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ValidateSuffix panicked on %q: %v", s, r)
			}
		}()
		_ = ValidateSuffix(s)
	})
}

func FuzzDeriveLegacyChains(f *testing.F) {
	seeds := []struct{ base, effective, suffixes string }{
		{"FIREFIK", "FIREFIK-v2", "v1"},
		{"FIREFIK", "FIREFIK-v2", "v1,v0,beta"},
		{"FIREFIK", "FIREFIK", ""},
		{"X", "X-y", "y"},
		{"", "", ""},
		{"FIREFIK", "FIREFIK-v3", "v1,v2,v1"},
		{"FIREFIK", "FIREFIK-v2", "v2"},
		{"FIREFIK", "FIREFIK-v2", ","},
		{"FIREFIK", "FIREFIK", ","},
		{"FIREFIK", "FIREFIK-x", strings.Repeat("a,", 100)},
		{"\x00", "\x00-x", "y"},
		{"FIREFIK", "FIREFIK-v2", "v1,,v2"},
		{"FIREFIK", "FIREFIK-v2", " v1, v2 "},
		{"a", "b", "c,d,e,f,g,h"},
		{"FIREFIK", "FIREFIK-спец", "спец,beta"},
		{"FIREFIK", "FIREFIK-v2", "v2'; DROP TABLE"},
		{"../base", "../base-x", "y"},
		{"FIREFIK", "FIREFIK-v2", strings.Repeat("x", 4096)},
		{"FIREFIK", "FIREFIK", "v1,v1,v1,v1,v1"},
		{"X", "X", ""},
		{"X", "X-", ""},
		{"X-", "X-", "x,-"},
	}
	for _, s := range seeds {
		f.Add(s.base, s.effective, s.suffixes)
	}
	f.Fuzz(func(t *testing.T, base, effective, suffixes string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DeriveLegacyChains panicked on base=%q effective=%q suffixes=%q: %v",
					base, effective, suffixes, r)
			}
		}()
		list := []string{}
		if suffixes != "" {
			for _, p := range splitCommaForFuzz(suffixes) {
				list = append(list, p)
			}
		}
		_ = DeriveLegacyChains(base, effective, list)
	})
}

func splitCommaForFuzz(s string) []string {
	var parts []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			parts = append(parts, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		parts = append(parts, cur)
	}
	return parts
}
