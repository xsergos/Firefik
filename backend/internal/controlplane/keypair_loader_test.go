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

	first, err := loader.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if first == nil {
		t.Fatal("nil first certificate")
	}

	time.Sleep(15 * time.Millisecond)
	writeKeypair(t, certPath, keyPath, "v2")

	second, err := loader.GetClientCertificate(nil)
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

	a, _ := loader.GetClientCertificate(nil)
	b, _ := loader.GetClientCertificate(nil)
	if a == nil || b == nil || a != b {
		t.Fatalf("expected cached cert reuse, a=%p b=%p", a, b)
	}
}

func TestKeypairLoader_GetServerCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "s.crt")
	keyPath := filepath.Join(dir, "s.key")
	writeKeypair(t, certPath, keyPath, "server")
	loader := NewKeypairLoader(certPath, keyPath)

	got, err := loader.GetServerCertificate(nil)
	if err != nil || got == nil {
		t.Fatalf("err=%v cert=%v", err, got)
	}
}

func TestKeypairLoader_LoadFailsAndNoCache(t *testing.T) {
	dir := t.TempDir()
	loader := NewKeypairLoader(filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key"))
	if _, err := loader.GetServerCertificate(nil); err == nil {
		t.Fatal("expected error when files don't exist and no cache")
	}
}

func TestKeyPairLoader_FallsBackToCacheOnReadError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	writeKeypair(t, certPath, keyPath, "first")
	loader := newKeyPairLoader(certPath, keyPath)

	first, err := loader.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(certPath, []byte("not pem"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := loader.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != first {
		t.Fatal("expected cached certificate to be returned when reload fails")
	}
}
