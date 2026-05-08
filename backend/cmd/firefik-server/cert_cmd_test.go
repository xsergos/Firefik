package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"firefik/internal/controlplane/mca"
)

func setupCA(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := mca.Init(dir, "spiffe://test.firefik/"); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRunCert_NoArgs(t *testing.T) {
	if err := runCert(nil); err == nil {
		t.Fatal("expected error when no subcommand")
	}
}

func TestRunCert_Help(t *testing.T) {
	if err := runCert([]string{"-h"}); err != nil {
		t.Fatalf("help should not error: %v", err)
	}
	if err := runCert([]string{"help"}); err != nil {
		t.Fatalf("help should not error: %v", err)
	}
}

func TestRunCert_UnknownSub(t *testing.T) {
	if err := runCert([]string{"frobnicate"}); err == nil {
		t.Fatal("expected error on unknown subcommand")
	}
}

func TestCertRotate_NoOpWhenHealthy(t *testing.T) {
	caDir := setupCA(t)
	prefix := filepath.Join(t.TempDir(), "cp-server")
	if err := certRotate([]string{
		"--ca-state-dir", caDir,
		"--server-cert-keypair", prefix,
		"--server-name", "test.local",
		"--server-cert-ttl", "8760h",
	}); err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	infoBefore, err := os.Stat(prefix + ".crt")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(15 * time.Millisecond)
	if err := certRotate([]string{
		"--ca-state-dir", caDir,
		"--server-cert-keypair", prefix,
		"--server-name", "test.local",
		"--server-cert-ttl", "8760h",
	}); err != nil {
		t.Fatalf("second rotate: %v", err)
	}
	infoAfter, _ := os.Stat(prefix + ".crt")
	if !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatal("healthy cert was rotated; expected no-op")
	}
}

func TestCertRotate_ForceRotates(t *testing.T) {
	caDir := setupCA(t)
	prefix := filepath.Join(t.TempDir(), "cp-server")
	if err := certRotate([]string{
		"--ca-state-dir", caDir,
		"--server-cert-keypair", prefix,
		"--server-name", "test.local",
		"--server-cert-ttl", "8760h",
	}); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(prefix + ".crt")
	time.Sleep(15 * time.Millisecond)
	if err := certRotate([]string{
		"--ca-state-dir", caDir,
		"--server-cert-keypair", prefix,
		"--server-name", "test.local",
		"--server-cert-ttl", "8760h",
		"--force",
	}); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(prefix + ".crt")
	if string(first) == string(second) {
		t.Fatal("--force did not produce a different cert")
	}
}

func TestCertRotate_MissingCAStateDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-ca")
	if err := certRotate([]string{"--ca-state-dir", missing}); err == nil {
		t.Fatal("expected error when CA state dir does not exist")
	}
}

func TestCertRotate_DefaultsToHostnameSAN(t *testing.T) {
	caDir := setupCA(t)
	prefix := filepath.Join(t.TempDir(), "cp-server")
	if err := certRotate([]string{
		"--ca-state-dir", caDir,
		"--server-cert-keypair", prefix,
		"--server-cert-ttl", "8760h",
	}); err != nil {
		t.Fatal(err)
	}
	cert, err := loadCertFile(prefix + ".crt")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(cert.DNSNames, "controlplane") {
		t.Fatalf("default SAN list missing 'controlplane': %v", cert.DNSNames)
	}
}

func TestSplitCSV(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{",,", nil},
		{"a", []string{"a"}},
		{"a, b ,, c", []string{"a", "b", "c"}},
	}
	for _, c := range cases {
		got := splitCSV(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("input %q: got %v want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("input %q[%d]: got %q want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestDefaultServerNames(t *testing.T) {
	names := defaultServerNames()
	if len(names) == 0 {
		t.Fatal("default server names is empty")
	}
	if !contains(names, "controlplane") {
		t.Fatalf("default names missing 'controlplane': %v", names)
	}
	for _, n := range names {
		if n != strings.ToLower(n) {
			t.Fatalf("default name %q is not lowercased", n)
		}
	}
}
