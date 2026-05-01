package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCmdEnrollMissingControlPlane(t *testing.T) {
	err := cmdEnroll([]string{"--agent-id", "x"})
	if err == nil || !strings.Contains(err.Error(), "control-plane") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestCmdEnrollSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"cert_pem":       "CERT",
			"key_pem":        "KEY",
			"bundle_pem":     "BUNDLE",
			"serial":         "DEAD",
			"spiffe_uri":     "spiffe://test/abc",
			"not_after_unix": time.Now().Add(time.Hour).Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	tmp := t.TempDir()
	out := captureStdout(t, func() {
		if err := cmdEnroll([]string{"--control-plane", srv.URL, "--agent-id", "abc", "--out", tmp, "--token", "tok"}); err != nil {
			t.Fatalf("enroll: %v", err)
		}
	})
	if !strings.Contains(out, "agent-id: abc") {
		t.Errorf("got %q", out)
	}
	for _, name := range []string{"client.crt", "client.key", "ca-bundle.pem"} {
		if _, err := os.Stat(filepath.Join(tmp, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
}

func TestCmdEnrollServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", 500)
	}))
	defer srv.Close()
	tmp := t.TempDir()
	err := cmdEnroll([]string{"--control-plane", srv.URL, "--agent-id", "abc", "--out", tmp})
	if err == nil || !strings.Contains(err.Error(), "enroll:") {
		t.Errorf("unexpected: %v", err)
	}
}

func TestCmdEnrollHostnameDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"cert_pem": "C", "key_pem": "K", "bundle_pem": "B", "serial": "1", "spiffe_uri": "u", "not_after_unix": time.Now().Add(time.Hour).Unix()})
	}))
	defer srv.Close()
	tmp := t.TempDir()
	if err := cmdEnroll([]string{"--control-plane", srv.URL, "--out", tmp}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
}

func TestCmdEnrollRenewSkippedWhenValid(t *testing.T) {
	tmp := t.TempDir()
	certPath := filepath.Join(tmp, "client.crt")
	if err := writeCertWithExpiry(certPath, time.Now().Add(168*time.Hour)); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := cmdEnroll([]string{"--control-plane", "http://example/", "--agent-id", "x", "--out", tmp, "--renew", "--renew-window", "10h"}); err != nil {
			t.Fatalf("enroll: %v", err)
		}
	})
	if !strings.Contains(out, "nothing to do") {
		t.Errorf("expected skip, got %q", out)
	}
}

func TestCmdEnrollRenewProceedsWhenExpiring(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"cert_pem": "C", "key_pem": "K", "bundle_pem": "B", "serial": "1", "spiffe_uri": "u", "not_after_unix": time.Now().Add(time.Hour).Unix()})
	}))
	defer srv.Close()

	tmp := t.TempDir()
	certPath := filepath.Join(tmp, "client.crt")
	if err := writeCertWithExpiry(certPath, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_ = captureStdout(t, func() {
		if err := cmdEnroll([]string{"--control-plane", srv.URL, "--agent-id", "x", "--out", tmp, "--renew", "--renew-window", "12h"}); err != nil {
			t.Fatalf("enroll: %v", err)
		}
	})
}

func TestLoadCertExpiry(t *testing.T) {
	tmp := t.TempDir()
	certPath := filepath.Join(tmp, "c.pem")
	expiry := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	if err := writeCertWithExpiry(certPath, expiry); err != nil {
		t.Fatal(err)
	}
	got, err := loadCertExpiry(certPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !got.Truncate(time.Second).Equal(expiry) {
		t.Errorf("got %v, want %v", got, expiry)
	}
}

func TestLoadCertExpiryMissing(t *testing.T) {
	if _, err := loadCertExpiry("/nonexistent/path"); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadCertExpiryNoPEM(t *testing.T) {
	tmp := t.TempDir()
	bad := filepath.Join(tmp, "bad")
	if err := os.WriteFile(bad, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCertExpiry(bad); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadCertExpiryBadDER(t *testing.T) {
	tmp := t.TempDir()
	bad := filepath.Join(tmp, "bad.pem")
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	if err := os.WriteFile(bad, pemBlock, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCertExpiry(bad); err == nil {
		t.Fatal("expected error")
	}
}

func writeCertWithExpiry(path string, expiry time.Time) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     expiry,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return os.WriteFile(path, pemBytes, 0o600)
}

var _ = fmt.Sprintf
