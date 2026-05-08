package main

import (
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
