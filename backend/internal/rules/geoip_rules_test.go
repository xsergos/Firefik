package rules

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"firefik/internal/docker"
	"firefik/internal/geoip"
)

func TestApplyGeoIP_NoDB_WithGeoRules(t *testing.T) {
	rs := &docker.FirewallRuleSet{
		Name:     "test",
		GeoBlock: []string{"CN"},
	}
	res := applyGeoIP(rs, nil)
	if res.Fatal == nil {
		t.Fatalf("expected Fatal error when DB missing and geoblock set")
	}
	if !errors.Is(res.Fatal, ErrGeoIPUnavailable) {
		t.Fatalf("expected ErrGeoIPUnavailable, got %v", res.Fatal)
	}
}

func TestApplyGeoIP_NoDB_NoGeoRules(t *testing.T) {
	rs := &docker.FirewallRuleSet{Name: "test"}
	res := applyGeoIP(rs, nil)
	if res.Fatal != nil {
		t.Fatalf("unexpected Fatal when no geo rules: %v", res.Fatal)
	}
}

func encStrR(s string) []byte {
	if len(s) >= 29 {
		panic("test helper supports short strings only")
	}
	out := []byte{byte((2 << 5) | len(s))}
	out = append(out, []byte(s)...)
	return out
}

func encUint16R(n uint16) []byte {
	if n == 0 {
		return []byte{byte(5 << 5)}
	}
	if n <= 0xff {
		return []byte{byte((5 << 5) | 1), byte(n)}
	}
	return []byte{byte((5 << 5) | 2), byte(n >> 8), byte(n)}
}

func encEmptySliceR() []byte { return []byte{0x00, 0x04} }

func encMapR(size int) []byte {
	if size >= 29 {
		panic("test helper supports small maps only")
	}
	return []byte{byte((7 << 5) | size)}
}

func writeStubGeoIPDB(t *testing.T) string {
	t.Helper()
	var data bytes.Buffer
	data.Write(encMapR(1))
	data.Write(encStrR("country"))
	data.Write(encMapR(1))
	data.Write(encStrR("iso_code"))
	data.Write(encStrR("US"))
	dataBytes := data.Bytes()

	const nodeCount = 1
	const recordSize = 24
	const dataPointer = nodeCount + 16

	var tree bytes.Buffer
	tree.WriteByte(byte(dataPointer >> 16))
	tree.WriteByte(byte(dataPointer >> 8))
	tree.WriteByte(byte(dataPointer))
	tree.WriteByte(byte(dataPointer >> 16))
	tree.WriteByte(byte(dataPointer >> 8))
	tree.WriteByte(byte(dataPointer))

	var meta bytes.Buffer
	meta.Write(encMapR(9))
	meta.Write(encStrR("node_count"))
	meta.Write(encUint16R(nodeCount))
	meta.Write(encStrR("record_size"))
	meta.Write(encUint16R(recordSize))
	meta.Write(encStrR("ip_version"))
	meta.Write(encUint16R(4))
	meta.Write(encStrR("database_type"))
	meta.Write(encStrR("firefik-test"))
	meta.Write(encStrR("languages"))
	meta.Write(encEmptySliceR())
	meta.Write(encStrR("binary_format_major_version"))
	meta.Write(encUint16R(2))
	meta.Write(encStrR("binary_format_minor_version"))
	meta.Write(encUint16R(0))
	meta.Write(encStrR("build_epoch"))
	meta.Write(encUint16R(0))
	meta.Write(encStrR("description"))
	meta.Write(encMapR(1))
	meta.Write(encStrR("en"))
	meta.Write(encStrR("firefik test"))

	var out bytes.Buffer
	out.Write(tree.Bytes())
	for i := 0; i < 16; i++ {
		out.WriteByte(0)
	}
	out.Write(dataBytes)
	out.WriteString("\xAB\xCD\xEFMaxMind.com")
	out.Write(meta.Bytes())

	dir := t.TempDir()
	p := filepath.Join(dir, "stub.mmdb")
	if err := os.WriteFile(p, out.Bytes(), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestApplyGeoIP_GeoBlockMatched(t *testing.T) {
	p := writeStubGeoIPDB(t)
	db, err := geoip.Open(p)
	if err != nil {
		t.Skipf("stub mmdb open failed: %v", err)
	}
	defer db.Close()

	rs := &docker.FirewallRuleSet{Name: "block", GeoBlock: []string{"US"}}
	res := applyGeoIP(rs, db)
	if res.Fatal != nil {
		t.Fatalf("unexpected fatal: %v", res.Fatal)
	}
	if len(rs.Blocklist) == 0 {
		t.Fatalf("expected Blocklist to be populated")
	}
}

func TestApplyGeoIP_GeoBlockNoMatch_Warning(t *testing.T) {
	p := writeStubGeoIPDB(t)
	db, err := geoip.Open(p)
	if err != nil {
		t.Skipf("stub mmdb open failed: %v", err)
	}
	defer db.Close()

	rs := &docker.FirewallRuleSet{Name: "block", GeoBlock: []string{"ZZ"}}
	res := applyGeoIP(rs, db)
	if res.Fatal != nil {
		t.Fatalf("unexpected fatal: %v", res.Fatal)
	}
	if len(res.Warnings) == 0 {
		t.Fatalf("expected warning for non-matching block")
	}
}

func TestApplyGeoIP_GeoAllowMatched(t *testing.T) {
	p := writeStubGeoIPDB(t)
	db, err := geoip.Open(p)
	if err != nil {
		t.Skipf("stub mmdb open failed: %v", err)
	}
	defer db.Close()

	rs := &docker.FirewallRuleSet{Name: "allow", GeoAllow: []string{"US"}}
	res := applyGeoIP(rs, db)
	if res.Fatal != nil {
		t.Fatalf("unexpected fatal: %v", res.Fatal)
	}
	if len(rs.Allowlist) == 0 {
		t.Fatalf("expected Allowlist populated")
	}
}

func TestApplyGeoIP_GeoAllowNoMatch_Fatal(t *testing.T) {
	p := writeStubGeoIPDB(t)
	db, err := geoip.Open(p)
	if err != nil {
		t.Skipf("stub mmdb open failed: %v", err)
	}
	defer db.Close()

	rs := &docker.FirewallRuleSet{Name: "allow", GeoAllow: []string{"ZZ"}}
	res := applyGeoIP(rs, db)
	if res.Fatal == nil {
		t.Fatalf("expected Fatal when geoallow has no networks")
	}
}

func TestApplyGeoIP_BothGeoBlockAndAllow(t *testing.T) {
	p := writeStubGeoIPDB(t)
	db, err := geoip.Open(p)
	if err != nil {
		t.Skipf("stub mmdb open failed: %v", err)
	}
	defer db.Close()

	rs := &docker.FirewallRuleSet{
		Name:     "both",
		GeoBlock: []string{"US"},
		GeoAllow: []string{"US"},
	}
	res := applyGeoIP(rs, db)
	if res.Fatal != nil {
		t.Fatalf("unexpected fatal: %v", res.Fatal)
	}
	if len(rs.Blocklist) == 0 || len(rs.Allowlist) == 0 {
		t.Fatalf("expected both lists populated")
	}
}
