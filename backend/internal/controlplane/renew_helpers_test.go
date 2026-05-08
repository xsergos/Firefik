package controlplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDialRenewClient_BadCAFile(t *testing.T) {
	if _, _, err := DialRenewClient(RenewGRPCDialConfig{
		Endpoint: "127.0.0.1:1",
		CertPath: "x", KeyPath: "y",
		CAPath: filepath.Join(t.TempDir(), "no-such"),
	}); err == nil {
		t.Fatal("expected error when CAPath is missing")
	}
}

func TestDialRenewClient_NotPEMCAFile(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, []byte("not pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := DialRenewClient(RenewGRPCDialConfig{
		Endpoint: "127.0.0.1:1", CertPath: "x", KeyPath: "y", CAPath: caPath,
	}); err == nil {
		t.Fatal("expected error on non-PEM CA bundle")
	}
}

func TestDialRenewClient_OK(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	rc, conn, err := DialRenewClient(RenewGRPCDialConfig{
		Endpoint: "127.0.0.1:1", CertPath: "x", KeyPath: "y", CAPath: caPath,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if rc == nil || conn == nil {
		t.Fatal("nil conn")
	}
	_ = conn.Close()
}

func TestCSRPubKeyMatchesPeer_Edge(t *testing.T) {
	if csrPubKeyMatchesPeer([]byte("not pem"), &x509.Certificate{}) {
		t.Fatal("non-PEM csr should not match")
	}
	if csrPubKeyMatchesPeer([]byte("-----BEGIN CERTIFICATE REQUEST-----\nzz\n-----END CERTIFICATE REQUEST-----\n"), &x509.Certificate{}) {
		t.Fatal("garbage CSR should not match")
	}
}

func TestSpiffeVerifier(t *testing.T) {
	v := spiffeVerifier("spiffe://prod/")
	if err := v(&x509.Certificate{}); err == nil {
		t.Fatal("expected error when peer has no SPIFFE SAN")
	}
}

func TestAgentIDFromCert_NoSAN(t *testing.T) {
	if got := agentIDFromCert(&x509.Certificate{}); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestEmitAudit_NilSafe(t *testing.T) {
	srv := &GRPCServer{}
	srv.emitAudit("x", nil)
}

func TestBoolStr(t *testing.T) {
	if boolStr(true) != "true" || boolStr(false) != "false" {
		t.Fatal("boolStr broken")
	}
}

func TestIncServerCertMetricsAreSafe(t *testing.T) {
	IncServerCertRenewed("near_expiry")
	IncServerCertRenewFailed("write_cert")
	IncCertRenewed()
	IncRenewRejected("rate_limited")
	IncCACertsIssued()
	IncMTLSRejected("trust_domain")
	SetAgentCertExpiry("a", "spiffe://x/agent/a", 7)
	AgentCertRenewedTotal.Inc()
	AgentCertRenewFailedTotal.WithLabelValues("rpc_error").Inc()
	AgentBundleRotatedTotal.Inc()
}
