package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

func writeTestCert(t *testing.T, dir string, ttl time.Duration, spiffeID string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(ttl),
	}
	if spiffeID != "" {
		u, err := url.Parse(spiffeID)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cert.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return path
}

func gaugeValue(t *testing.T, agentID, spiffeID string) float64 {
	t.Helper()
	g, err := AgentCertDaysUntilExpiry.GetMetricWithLabelValues(agentID, spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	pb := &dto.Metric{}
	if err := g.Write(pb); err != nil {
		t.Fatal(err)
	}
	return pb.Gauge.GetValue()
}

func TestLoadAgentCert_Valid(t *testing.T) {
	dir := t.TempDir()
	path := writeTestCert(t, dir, 30*24*time.Hour, "spiffe://example.org/agent/test")
	cert, err := loadAgentCert(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if firstURISAN(cert) != "spiffe://example.org/agent/test" {
		t.Errorf("uri san mismatch: %v", cert.URIs)
	}
}

func TestLoadAgentCert_MissingFile(t *testing.T) {
	if _, err := loadAgentCert(filepath.Join(t.TempDir(), "absent.pem")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadAgentCert_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAgentCert(path); err == nil {
		t.Fatal("expected error for invalid pem")
	}
}

func TestFirstURISAN_NoURIs(t *testing.T) {
	if got := firstURISAN(&x509.Certificate{}); got != "" {
		t.Errorf("got %q, want empty", got)
	}
	if got := firstURISAN(nil); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestCertExpiryWatcher_Observe(t *testing.T) {
	dir := t.TempDir()
	path := writeTestCert(t, dir, 14*24*time.Hour, "spiffe://example.org/agent/abc")
	w := &CertExpiryWatcher{CertPath: path, AgentID: "agent-abc"}
	w.observe(slog.New(slog.NewTextHandler(io.Discard, nil)))

	v := gaugeValue(t, "agent-abc", "spiffe://example.org/agent/abc")
	if v < 13 || v > 14.5 {
		t.Errorf("days until expiry %v not in [13, 14.5]", v)
	}
}

func TestCertExpiryWatcher_BadFileLogs(t *testing.T) {
	w := &CertExpiryWatcher{CertPath: filepath.Join(t.TempDir(), "absent.pem"), AgentID: "x"}
	w.observe(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestCertExpiryWatcher_RunNoPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	w := &CertExpiryWatcher{CertPath: ""}
	w.Run(ctx)
}

func TestCertExpiryWatcher_RunCancellation(t *testing.T) {
	dir := t.TempDir()
	path := writeTestCert(t, dir, 24*time.Hour, "")
	ctx, cancel := context.WithCancel(context.Background())
	w := &CertExpiryWatcher{
		CertPath: path,
		AgentID:  "agent-cancel",
		Interval: 10 * time.Millisecond,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
