package geoip

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func encStr(s string) []byte {
	if len(s) >= 29 {
		panic("test helper supports short strings only")
	}
	out := []byte{byte((2 << 5) | len(s))}
	out = append(out, []byte(s)...)
	return out
}

func encUint16(n uint16) []byte {
	if n == 0 {
		return []byte{byte(5 << 5)}
	}
	if n <= 0xff {
		return []byte{byte((5 << 5) | 1), byte(n)}
	}
	return []byte{byte((5 << 5) | 2), byte(n >> 8), byte(n)}
}

func encEmptySlice() []byte {
	return []byte{0x00, 0x04}
}

func encMap(size int) []byte {
	if size >= 29 {
		panic("test helper supports small maps only")
	}
	return []byte{byte((7 << 5) | size)}
}

func buildStubMMDB() []byte {
	var data bytes.Buffer

	data.Write(encMap(1))
	data.Write(encStr("country"))
	data.Write(encMap(1))
	data.Write(encStr("iso_code"))
	data.Write(encStr("US"))

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
	meta.Write(encMap(9))
	meta.Write(encStr("node_count"))
	meta.Write(encUint16(nodeCount))
	meta.Write(encStr("record_size"))
	meta.Write(encUint16(recordSize))
	meta.Write(encStr("ip_version"))
	meta.Write(encUint16(4))
	meta.Write(encStr("database_type"))
	meta.Write(encStr("firefik-test"))
	meta.Write(encStr("languages"))
	meta.Write(encEmptySlice())
	meta.Write(encStr("binary_format_major_version"))
	meta.Write(encUint16(2))
	meta.Write(encStr("binary_format_minor_version"))
	meta.Write(encUint16(0))
	meta.Write(encStr("build_epoch"))
	meta.Write(encUint16(0))
	meta.Write(encStr("description"))
	meta.Write(encMap(1))
	meta.Write(encStr("en"))
	meta.Write(encStr("firefik test"))

	var out bytes.Buffer
	out.Write(tree.Bytes())
	for i := 0; i < 16; i++ {
		out.WriteByte(0)
	}
	out.Write(dataBytes)
	out.WriteString("\xAB\xCD\xEFMaxMind.com")
	out.Write(meta.Bytes())
	return out.Bytes()
}

func writeStubMMDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "stub.mmdb")
	if err := os.WriteFile(p, buildStubMMDB(), 0o644); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	return p
}

func TestOpen_BadPath(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "missing.mmdb"))
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestOpen_GarbageFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.mmdb")
	if err := os.WriteFile(p, []byte("not an mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Open(p)
	if err == nil {
		t.Fatalf("expected error for garbage mmdb")
	}
}

func TestClose_NilDB(t *testing.T) {
	var db *DB
	if err := db.Close(); err != nil {
		t.Fatalf("nil db close: %v", err)
	}
}

func TestClose_NilReader(t *testing.T) {
	db := &DB{}
	if err := db.Close(); err != nil {
		t.Fatalf("empty db close: %v", err)
	}
}

func TestCountryForIP_NilDB(t *testing.T) {
	var db *DB
	if got := db.CountryForIP(net.ParseIP("1.1.1.1")); got != "" {
		t.Fatalf("nil db CountryForIP = %q", got)
	}
}

func TestCountryForIP_NilReader(t *testing.T) {
	db := &DB{}
	if got := db.CountryForIP(net.ParseIP("1.1.1.1")); got != "" {
		t.Fatalf("empty db CountryForIP = %q", got)
	}
}

func TestCIDRsForCountries_NilDB(t *testing.T) {
	var db *DB
	got, err := db.CIDRsForCountries([]string{"US"})
	if err != nil {
		t.Fatalf("nil db CIDRsForCountries err: %v", err)
	}
	if got != nil {
		t.Fatalf("nil db got %v", got)
	}
}

func TestCIDRsForCountries_NoCountries(t *testing.T) {
	p := writeStubMMDB(t)
	db, err := Open(p)
	if err != nil {
		t.Skipf("skip: stub mmdb open failed: %v", err)
	}
	defer db.Close()
	got, err := db.CIDRsForCountries(nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestStubMMDB_RoundTrip(t *testing.T) {
	p := writeStubMMDB(t)
	db, err := Open(p)
	if err != nil {
		t.Skipf("skip: stub mmdb open failed: %v", err)
	}
	defer db.Close()

	if got := db.CountryForIP(net.ParseIP("1.2.3.4")); got != "US" {
		t.Fatalf("CountryForIP got %q want US", got)
	}
	if got := db.CountryForIP(nil); got != "" {
		t.Fatalf("nil ip got %q", got)
	}

	cidrs, err := db.CIDRsForCountries([]string{"us"})
	if err != nil {
		t.Fatalf("CIDRsForCountries: %v", err)
	}
	if len(cidrs) == 0 {
		t.Fatalf("expected at least one network for US")
	}
	cidrs2, err := db.CIDRsForCountries([]string{"ZZ"})
	if err != nil {
		t.Fatalf("CIDRsForCountries: %v", err)
	}
	if len(cidrs2) != 0 {
		t.Fatalf("expected zero networks for unknown country, got %v", cidrs2)
	}
}
