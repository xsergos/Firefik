package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	pb "firefik/internal/controlplane/gen/controlplanev1"

	"google.golang.org/grpc"
)

type fakeRenewClient struct {
	calls atomic.Int32
	last  *pb.RenewCertRequest
	resp  *pb.RenewCertResponse
	err   error
}

func (f *fakeRenewClient) RenewCert(_ context.Context, in *pb.RenewCertRequest, _ ...grpc.CallOption) (*pb.RenewCertResponse, error) {
	f.calls.Add(1)
	f.last = in
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

type testPKI struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
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
	return &testPKI{caCert: caCert, caKey: caKey}
}

func (p *testPKI) issueClient(t *testing.T, agentID string, ttl time.Duration) (cert []byte, key []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &priv.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
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

	mock := &fakeRenewClient{}
	r := &CertRenewer{
		AgentID:     "agent-a",
		CertPath:    certPath,
		KeyPath:     keyPath,
		Client:      mock,
		RenewBefore: 24 * time.Hour,
		Logger:      slog.Default(),
	}
	r.tick(context.Background(), slog.Default())
	if mock.calls.Load() != 0 {
		t.Fatalf("expected no RPC calls, got %d", mock.calls.Load())
	}
}

func TestCertRenewer_HappyPath(t *testing.T) {
	pki := makeTestPKI(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	bundlePath := filepath.Join(dir, "bundle.pem")
	certPEM, keyPEM := pki.issueClient(t, "agent-a", time.Hour)
	writeAll(t, map[string][]byte{certPath: certPEM, keyPath: keyPEM})

	newCert, _ := pki.issueClient(t, "agent-a", 10*24*time.Hour)
	mock := &fakeRenewClient{
		resp: &pb.RenewCertResponse{
			CertPem:     newCert,
			BundlePem:   []byte("ROOT BUNDLE"),
			Serial:      "deadbeef",
			ExpiresUnix: time.Now().Add(10 * 24 * time.Hour).Unix(),
		},
	}

	rotated := make(chan struct{}, 1)
	r := &CertRenewer{
		AgentID:     "agent-a",
		CertPath:    certPath,
		KeyPath:     keyPath,
		BundlePath:  bundlePath,
		Client:      mock,
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
	if got, _ := os.ReadFile(certPath); string(got) != string(newCert) {
		t.Fatal("cert was not replaced")
	}
	if got, _ := os.ReadFile(keyPath); string(got) != string(keyPEM) {
		t.Fatal("key changed: CSR-mode renew must keep the private key untouched")
	}
	if got, _ := os.ReadFile(bundlePath); string(got) != "ROOT BUNDLE" {
		t.Fatal("bundle was not written")
	}
	if mock.last == nil || mock.last.AgentId != "agent-a" || len(mock.last.CsrPem) == 0 {
		t.Fatalf("RPC was not invoked correctly: %+v", mock.last)
	}
}

func TestCertRenewer_BundleRolloverOnlyOnChange(t *testing.T) {
	pki := makeTestPKI(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	bundlePath := filepath.Join(dir, "bundle.pem")
	certPEM, keyPEM := pki.issueClient(t, "agent-a", time.Hour)
	writeAll(t, map[string][]byte{certPath: certPEM, keyPath: keyPEM, bundlePath: []byte("ROOT BUNDLE")})

	newCert, _ := pki.issueClient(t, "agent-a", 10*24*time.Hour)
	mock := &fakeRenewClient{
		resp: &pb.RenewCertResponse{
			CertPem:     newCert,
			BundlePem:   []byte("ROOT BUNDLE"),
			Serial:      "abc",
			ExpiresUnix: time.Now().Add(10 * 24 * time.Hour).Unix(),
		},
	}
	infoBefore, _ := os.Stat(bundlePath)

	r := &CertRenewer{
		AgentID:     "agent-a",
		CertPath:    certPath,
		KeyPath:     keyPath,
		BundlePath:  bundlePath,
		Client:      mock,
		RenewBefore: 24 * time.Hour,
		Logger:      slog.Default(),
	}
	r.tick(context.Background(), slog.Default())
	infoAfter, _ := os.Stat(bundlePath)
	if !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatal("bundle was rewritten despite identical content")
	}
}

func TestCertRenewer_RPCError(t *testing.T) {
	pki := makeTestPKI(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	certPEM, keyPEM := pki.issueClient(t, "agent-a", time.Hour)
	writeAll(t, map[string][]byte{certPath: certPEM, keyPath: keyPEM})

	mock := &fakeRenewClient{err: errors.New("boom")}
	r := &CertRenewer{
		AgentID:     "agent-a",
		CertPath:    certPath,
		KeyPath:     keyPath,
		Client:      mock,
		RenewBefore: 24 * time.Hour,
		Logger:      slog.Default(),
	}
	r.tick(context.Background(), slog.Default())

	if got, _ := os.ReadFile(certPath); string(got) != string(certPEM) {
		t.Fatal("cert was rotated despite RPC error")
	}
}

func TestCertRenewer_Run_StopsOnContextCancel(t *testing.T) {
	pki := makeTestPKI(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	certPEM, keyPEM := pki.issueClient(t, "agent", 10*24*time.Hour)
	writeAll(t, map[string][]byte{certPath: certPEM, keyPath: keyPEM})

	ctx, cancel := context.WithCancel(context.Background())
	r := &CertRenewer{
		AgentID:     "agent",
		CertPath:    certPath,
		KeyPath:     keyPath,
		Client:      &fakeRenewClient{},
		RenewBefore: time.Hour,
		Interval:    50 * time.Millisecond,
		Logger:      slog.Default(),
	}
	done := make(chan struct{})
	go func() {
		_ = r.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop on ctx cancel")
	}
}

func TestCertRenewer_Run_NoOpWithoutClient(t *testing.T) {
	r := &CertRenewer{}
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("expected nil err for misconfigured renewer, got %v", err)
	}
}

func TestCertRenewer_Tick_LoadCertError(t *testing.T) {
	r := &CertRenewer{
		AgentID:     "x",
		CertPath:    filepath.Join(t.TempDir(), "missing.crt"),
		KeyPath:     filepath.Join(t.TempDir(), "missing.key"),
		Client:      &fakeRenewClient{},
		RenewBefore: time.Hour,
		Logger:      slog.Default(),
	}
	r.Tick(context.Background())
}

func TestCertRenewer_Logger_Default(t *testing.T) {
	r := &CertRenewer{}
	if r.logger() == nil {
		t.Fatal("logger() must never return nil")
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	if _, err := parsePrivateKeyPEM([]byte("not pem")); err == nil {
		t.Fatal("expected error on non-PEM")
	}
	if _, err := parsePrivateKeyPEM([]byte("-----BEGIN UNKNOWN-----\nfoo\n-----END UNKNOWN-----\n")); err == nil {
		t.Fatal("expected error on unsupported PEM type")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if _, err := parsePrivateKeyPEM(pemBytes); err != nil {
		t.Fatalf("EC PRIVATE KEY parse: %v", err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if _, err := parsePrivateKeyPEM(pemBytes); err != nil {
		t.Fatalf("PKCS8 parse: %v", err)
	}
	bad := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{0x00}})
	if _, err := parsePrivateKeyPEM(bad); err == nil {
		t.Fatal("expected error on garbage EC PRIVATE KEY")
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
