package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type testPKI struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	caPEM      []byte
	serverCert tls.Certificate
}

func makeTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost", "127.0.0.1"},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return &testPKI{
		caCert: caCert,
		caKey:  caKey,
		caPEM:  caPEM,
		serverCert: tls.Certificate{
			Certificate: [][]byte{srvDER},
			PrivateKey:  srvKey,
		},
	}
}

func (p *testPKI) issueClient(t *testing.T, agentID string, ttl time.Duration) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://test.firefik/agent/" + agentID)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: agentID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func writeAll(t *testing.T, paths map[string][]byte) {
	t.Helper()
	for p, data := range paths {
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCertRenewer_NotInWindow(t *testing.T) {
	pki := makeTestPKI(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	certPEM, keyPEM := pki.issueClient(t, "agent-a", 10*24*time.Hour)
	writeAll(t, map[string][]byte{certPath: certPEM, keyPath: keyPEM})

	var calls int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	srv.Start()
	defer srv.Close()

	r := &CertRenewer{
		AgentID:     "agent-a",
		CertPath:    certPath,
		KeyPath:     keyPath,
		Endpoint:    srv.URL,
		RenewBefore: 24 * time.Hour,
		Logger:      slog.Default(),
	}
	r.tick(context.Background(), slog.Default())
	if calls != 0 {
		t.Fatalf("expected no HTTP calls, got %d", calls)
	}
}

func TestCertRenewer_HappyPath(t *testing.T) {
	pki := makeTestPKI(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	caPath := filepath.Join(dir, "ca.pem")
	certPEM, keyPEM := pki.issueClient(t, "agent-a", time.Hour)
	writeAll(t, map[string][]byte{certPath: certPEM, keyPath: keyPEM, caPath: pki.caPEM})

	newCert, newKey := pki.issueClient(t, "agent-a", 10*24*time.Hour)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/renew", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no peer", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RenewResponse{
			CertPEM:      string(newCert),
			KeyPEM:       string(newKey),
			BundlePEM:    string(pki.caPEM),
			Serial:       "deadbeef",
			SPIFFEURI:    "spiffe://test.firefik/agent/agent-a",
			NotAfterUnix: time.Now().Add(10 * 24 * time.Hour).Unix(),
		})
	})

	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(pki.caCert)

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	rotated := make(chan struct{}, 1)
	r := &CertRenewer{
		AgentID:     "agent-a",
		CertPath:    certPath,
		KeyPath:     keyPath,
		BundlePath:  filepath.Join(dir, "bundle.pem"),
		CAPath:      caPath,
		Endpoint:    srv.URL,
		RenewBefore: 24 * time.Hour,
		Logger:      slog.Default(),
		OnRotated:   func() { rotated <- struct{}{} },
	}
	r.tick(context.Background(), slog.Default())

	select {
	case <-rotated:
	case <-time.After(time.Second):
		t.Fatal("OnRotated not called")
	}

	got, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newCert) {
		t.Fatal("cert file was not replaced")
	}
	gotKey, _ := os.ReadFile(keyPath)
	if string(gotKey) != string(keyPEM) {
		t.Fatal("key file changed: CSR-mode renew must leave the private key untouched")
	}
	_ = newKey
	gotBundle, _ := os.ReadFile(r.BundlePath)
	if string(gotBundle) != string(pki.caPEM) {
		t.Fatal("bundle file was not replaced")
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Logf("key mode=%o (expected 0o600 on POSIX, may differ on Windows)", mode)
	}
}

func TestCertRenewer_HTTPError(t *testing.T) {
	pki := makeTestPKI(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	caPath := filepath.Join(dir, "ca.pem")
	certPEM, keyPEM := pki.issueClient(t, "agent-a", time.Hour)
	writeAll(t, map[string][]byte{certPath: certPEM, keyPath: keyPEM, caPath: pki.caPEM})

	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(pki.caCert)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	r := &CertRenewer{
		AgentID:     "agent-a",
		CertPath:    certPath,
		KeyPath:     keyPath,
		CAPath:      caPath,
		Endpoint:    srv.URL,
		RenewBefore: 24 * time.Hour,
		Logger:      slog.Default(),
	}
	r.tick(context.Background(), slog.Default())

	got, _ := os.ReadFile(certPath)
	if string(got) != string(certPEM) {
		t.Fatal("cert was rotated despite server error")
	}
}

func TestWriteFileAtomic_AtomicReplace(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(target, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "new" {
		t.Fatalf("got %q", got)
	}
	if _, err := os.Stat(target + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file was not cleaned up")
	}
}
