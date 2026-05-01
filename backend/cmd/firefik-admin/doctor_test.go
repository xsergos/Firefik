package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCapBitBits(t *testing.T) {
	cases := map[string]uint{
		"CAP_NET_ADMIN": 12,
		"CAP_NET_RAW":   13,
		"CAP_SYS_ADMIN": 21,
	}
	for name, want := range cases {
		bit, ok := capBit(name)
		if !ok || bit != want {
			t.Errorf("capBit(%q) = (%d, %v), want (%d, true)", name, bit, ok, want)
		}
	}
	if _, ok := capBit("CAP_UNKNOWN"); ok {
		t.Errorf("capBit should reject unknown capability")
	}
}

func TestCapHasBit(t *testing.T) {
	if !capHasBit("00001000", 12) {
		t.Errorf("expected bit 12 in 0x00001000")
	}
	if capHasBit("00001000", 13) {
		t.Errorf("bit 13 should not be set in 0x00001000")
	}
	if !capHasBit("ffffffff", 21) {
		t.Errorf("bit 21 should be set in 0xffffffff")
	}
}

func TestCheckAuditPathSkipsEmpty(t *testing.T) {
	c := checkAuditPath("")
	if !c.Pass {
		t.Errorf("empty path should pass (stdout fallback): %+v", c)
	}
}

func TestCheckAuditPathWritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	c := checkAuditPath(path)
	if !c.Pass {
		t.Errorf("writable tempdir path should pass: %+v", c)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("audit-path check should have created the file: %v", err)
	}
}

func TestCheckAuditPathMissingDir(t *testing.T) {
	c := checkAuditPath("/this/path/really/should/not/exist/audit.jsonl")
	if c.Pass {
		t.Errorf("nonexistent dir should fail: %+v", c)
	}
	if !strings.Contains(c.Hint, "mkdir") {
		t.Errorf("hint should mention mkdir: %q", c.Hint)
	}
}

func TestCheckGeoIPAbsent(t *testing.T) {
	c := checkGeoIP("/does/not/exist.mmdb", 30*24*time.Hour)
	if !c.Pass {
		t.Errorf("absent GeoIP DB should pass (optional feature): %+v", c)
	}
	if !strings.Contains(c.Detail, "absent") {
		t.Errorf("detail should mention absent: %q", c.Detail)
	}
}

func TestCheckGeoIPStale(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "GeoLite2-Country.mmdb")
	if err := os.WriteFile(path, []byte("fake"), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}
	old := time.Now().Add(-30 * 24 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	c := checkGeoIP(path, 14*24*time.Hour)
	if c.Pass {
		t.Errorf("stale GeoIP DB should fail")
	}
}

func TestCheckGeoIPFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "GeoLite2-Country.mmdb")
	if err := os.WriteFile(path, []byte("fake-but-fresh"), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}
	c := checkGeoIP(path, 14*24*time.Hour)
	if !c.Pass {
		t.Errorf("fresh GeoIP DB should pass: %+v", c)
	}
}

func TestContainsModule(t *testing.T) {
	sample := "ip_tables 32768 2 - Live 0x0000000000000000\nnf_tables 237568 0 - Live 0x0000000000000000\n"
	if !containsModule(sample, "ip_tables") {
		t.Errorf("expected ip_tables in /proc/modules sample")
	}
	if containsModule(sample, "xt_owner") {
		t.Errorf("xt_owner should not be found")
	}
}

func TestContainsBuiltin(t *testing.T) {
	sample := "kernel/net/netfilter/x_tables.ko\nkernel/net/ipv4/netfilter/ip_tables.ko\n"
	if !containsBuiltin(sample, "ip_tables") {
		t.Errorf("ip_tables should be found as builtin")
	}
	if containsBuiltin(sample, "nf_tables") {
		t.Errorf("nf_tables should not be in sample")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		42:              "42B",
		1024:            "1.0KB",
		1024 * 1024 * 2: "2.0MB",
	}
	for n, want := range cases {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
