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

func writeKeypair(t *testing.T, certPath, keyPath, cn string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestKeyPairLoader_HotReload(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")

	writeKeypair(t, certPath, keyPath, "v1")
	loader := newKeyPairLoader(certPath, keyPath)

	first, err := loader.getClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if first == nil {
		t.Fatal("nil first certificate")
	}

	time.Sleep(15 * time.Millisecond)
	writeKeypair(t, certPath, keyPath, "v2")

	second, err := loader.getClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("loader did not detect file mtime change")
	}
}

func TestKeyPairLoader_CacheSticks(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	writeKeypair(t, certPath, keyPath, "stable")
	loader := newKeyPairLoader(certPath, keyPath)

	a, _ := loader.getClientCertificate(nil)
	b, _ := loader.getClientCertificate(nil)
	if a == nil || b == nil || a != b {
		t.Fatalf("expected cached cert reuse, a=%p b=%p", a, b)
	}
}

func TestKeyPairLoader_FallsBackToCacheOnReadError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	writeKeypair(t, certPath, keyPath, "first")
	loader := newKeyPairLoader(certPath, keyPath)

	first, err := loader.getClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(certPath, []byte("not pem"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := loader.getClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != first {
		t.Fatal("expected cached certificate to be returned when reload fails")
	}
}
