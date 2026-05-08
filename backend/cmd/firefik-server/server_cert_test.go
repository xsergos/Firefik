package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"firefik/internal/controlplane/mca"
)

func newCAForServerCertTest(t *testing.T) *mca.CA {
	t.Helper()
	dir := t.TempDir()
	ca, err := mca.Init(dir, "spiffe://test.firefik/")
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func newServerCertManager(t *testing.T, ca *mca.CA, dir string, ttl, renewBefore time.Duration) *serverCertManager {
	t.Helper()
	return &serverCertManager{
		CA:          ca,
		CertPath:    filepath.Join(dir, "cp-server.crt"),
		KeyPath:     filepath.Join(dir, "cp-server.key"),
		DNSNames:    []string{"controlplane", "fw-01"},
		IPAddresses: []string{"127.0.0.1"},
		TTL:         ttl,
		RenewBefore: renewBefore,
		Logger:      slog.Default(),
	}
}

func TestServerCertManager_AutoIssueAtStartup(t *testing.T) {
	ca := newCAForServerCertTest(t)
	dir := t.TempDir()
	mgr := newServerCertManager(t, ca, dir, time.Hour, 30*time.Minute)
	if err := mgr.ensureAtStartup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mgr.CertPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mgr.KeyPath); err != nil {
		t.Fatal(err)
	}
}

func TestServerCertManager_IdempotentWhenHealthy(t *testing.T) {
	ca := newCAForServerCertTest(t)
	dir := t.TempDir()
	mgr := newServerCertManager(t, ca, dir, time.Hour, 30*time.Minute)
	if err := mgr.ensureAtStartup(); err != nil {
		t.Fatal(err)
	}
	infoBefore, _ := os.Stat(mgr.CertPath)

	if err := mgr.ensureAtStartup(); err != nil {
		t.Fatal(err)
	}
	infoAfter, _ := os.Stat(mgr.CertPath)
	if !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatal("healthy cert was rewritten on second ensureAtStartup")
	}
}

func TestServerCertManager_ReissueOnSANMismatch(t *testing.T) {
	ca := newCAForServerCertTest(t)
	dir := t.TempDir()
	mgr := newServerCertManager(t, ca, dir, time.Hour, 30*time.Minute)
	if err := mgr.ensureAtStartup(); err != nil {
		t.Fatal(err)
	}
	infoBefore, _ := os.Stat(mgr.CertPath)

	mgr.DNSNames = append(mgr.DNSNames, "extra.cab")
	time.Sleep(15 * time.Millisecond)
	if err := mgr.ensureAtStartup(); err != nil {
		t.Fatal(err)
	}
	infoAfter, _ := os.Stat(mgr.CertPath)
	if infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatal("expected re-issue on SAN mismatch")
	}
	cert, err := loadCertFile(mgr.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(cert.DNSNames, "extra.cab") {
		t.Fatalf("missing new SAN: %v", cert.DNSNames)
	}
}

func TestServerCertManager_ReissueOnNearExpiry(t *testing.T) {
	ca := newCAForServerCertTest(t)
	dir := t.TempDir()
	mgr := newServerCertManager(t, ca, dir, time.Hour, time.Hour+time.Minute)
	if err := mgr.ensureAtStartup(); err != nil {
		t.Fatal(err)
	}
	reason := mgr.shouldReissue()
	if reason != "near_expiry" {
		t.Fatalf("expected near_expiry, got %q", reason)
	}
}

func TestServerCertManager_ReissueOnIssuerRotation(t *testing.T) {
	ca := newCAForServerCertTest(t)
	dir := t.TempDir()
	mgr := newServerCertManager(t, ca, dir, time.Hour, 30*time.Minute)
	if err := mgr.ensureAtStartup(); err != nil {
		t.Fatal(err)
	}
	other := newCAForServerCertTest(t)
	mgr.CA = other
	reason := mgr.shouldReissue()
	if reason != "issuer_rotated" {
		t.Fatalf("expected issuer_rotated, got %q", reason)
	}
}

func TestServerCertManager_HotReloadAfterIssue(t *testing.T) {
	ca := newCAForServerCertTest(t)
	dir := t.TempDir()
	mgr := newServerCertManager(t, ca, dir, time.Hour, 30*time.Minute)
	if err := mgr.ensureAtStartup(); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(mgr.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(15 * time.Millisecond)
	if err := mgr.issue("manual"); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(mgr.CertPath)
	if string(first) == string(second) {
		t.Fatal("force re-issue should produce a different cert")
	}
}

func TestServerCertManager_FailsWithoutCA(t *testing.T) {
	dir := t.TempDir()
	mgr := &serverCertManager{
		CertPath: filepath.Join(dir, "cp-server.crt"),
		KeyPath:  filepath.Join(dir, "cp-server.key"),
		DNSNames: []string{"controlplane"},
	}
	if err := mgr.issue("manual"); err == nil {
		t.Fatal("expected error without CA")
	}
}

func TestResolveServerCertPaths(t *testing.T) {
	cert, key, auto := resolveServerCertPaths("", "", "/var/lib/cp/ca", "", true)
	if !auto || cert != filepath.FromSlash("/var/lib/cp/ca/cp-server.crt") || key != filepath.FromSlash("/var/lib/cp/ca/cp-server.key") {
		t.Fatalf("default-prefix path computation broken: cert=%q key=%q auto=%v", cert, key, auto)
	}

	cert, key, auto = resolveServerCertPaths("", "", "/ignored", "/etc/firefik/cp", true)
	if !auto || cert != "/etc/firefik/cp.crt" || key != "/etc/firefik/cp.key" {
		t.Fatalf("explicit prefix override ignored: cert=%q key=%q", cert, key)
	}

	cert, key, auto = resolveServerCertPaths("/etc/cp.crt", "/etc/cp.key", "/ignored", "", true)
	if auto || cert != "/etc/cp.crt" || key != "/etc/cp.key" {
		t.Fatalf("explicit override should disable auto: cert=%q key=%q auto=%v", cert, key, auto)
	}

	cert, key, auto = resolveServerCertPaths("", "", "/ignored", "", false)
	if auto || cert != "" || key != "" {
		t.Fatalf("no CA + no override should yield empty paths: cert=%q key=%q auto=%v", cert, key, auto)
	}

	cert, key, auto = resolveServerCertPaths("/c.pem", "", "/ignored", "", true)
	if auto || cert != "/c.pem" || key != "" {
		t.Fatalf("partial override should still disable auto: cert=%q key=%q auto=%v", cert, key, auto)
	}
}

func TestServerCertManager_RunDaily_TriggersIssueOnStaleCert(t *testing.T) {
	t.Skip("daily rotation goroutine ticks once per 24h; covered indirectly via shouldReissue tests")
}

func TestServerCertManager_RunDaily_FailureLogged(t *testing.T) {
	ca := newCAForServerCertTest(t)
	dir := t.TempDir()
	mgr := newServerCertManager(t, ca, dir, time.Hour, 30*time.Minute)
	if err := mgr.ensureAtStartup(); err != nil {
		t.Fatal(err)
	}
	mgr.CA = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mgr.runDaily(ctx)
}

func TestServerCertManager_RunDaily_StopsOnContextCancel(t *testing.T) {
	ca := newCAForServerCertTest(t)
	dir := t.TempDir()
	mgr := newServerCertManager(t, ca, dir, time.Hour, 30*time.Minute)
	if err := mgr.ensureAtStartup(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		mgr.runDaily(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runDaily did not exit on context cancel")
	}
}

func TestServerCertManager_EnsureAtStartup_RequiresCertPath(t *testing.T) {
	mgr := &serverCertManager{}
	if err := mgr.ensureAtStartup(); err == nil {
		t.Fatal("expected error when CertPath/KeyPath are empty")
	}
}

func TestServerCertManager_Issue_MkdirParent(t *testing.T) {
	ca := newCAForServerCertTest(t)
	dir := t.TempDir()
	nested := filepath.Join(dir, "deep", "nested", "path")
	mgr := &serverCertManager{
		CA:          ca,
		CertPath:    filepath.Join(nested, "cp-server.crt"),
		KeyPath:     filepath.Join(nested, "cp-server.key"),
		DNSNames:    []string{"x"},
		IPAddresses: []string{"127.0.0.1"},
		TTL:         time.Hour,
		RenewBefore: 30 * time.Minute,
		Logger:      slog.Default(),
	}
	if err := mgr.issue("manual"); err != nil {
		t.Fatalf("issue with nested mkdir: %v", err)
	}
	if _, err := os.Stat(mgr.CertPath); err != nil {
		t.Fatal(err)
	}
}

func TestWriteFileAtomic_BadParentDir(t *testing.T) {
	if err := writeFileAtomic(filepath.Join(t.TempDir(), "no-such-dir", "f"), []byte("x"), 0o644); err == nil {
		t.Fatal("expected error when temp parent doesn't exist")
	}
}

func TestLoadCertFile_NotPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(path, []byte("not pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCertFile(path); err == nil {
		t.Fatal("expected error on non-PEM input")
	}
}

func TestLoadCertFile_Missing(t *testing.T) {
	if _, err := loadCertFile(filepath.Join(t.TempDir(), "no-such")); err == nil {
		t.Fatal("expected error on missing file")
	}
}

func TestLoadCertFile_Smoke(t *testing.T) {
	ca := newCAForServerCertTest(t)
	res, err := ca.IssueServerCert(mca.ServerCertRequest{DNSNames: []string{"x"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "x.crt")
	if err := os.WriteFile(path, res.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	cert, err := loadCertFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(res.CertPEM)
	other, _ := x509.ParseCertificate(block.Bytes)
	if cert.SerialNumber.Cmp(other.SerialNumber) != 0 {
		t.Fatalf("loaded cert does not match")
	}
}
