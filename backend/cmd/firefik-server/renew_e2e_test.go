package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"firefik/internal/controlplane"
	"firefik/internal/controlplane/mca"
)

func TestE2E_EnrollRenewRevoke(t *testing.T) {
	caDir := t.TempDir()
	ca, err := mca.Init(caDir, testTrustDomain)
	if err != nil {
		t.Fatal(err)
	}

	srv := startTestCPServer(t, ca, "")
	defer srv.Close()

	bundleDir := t.TempDir()
	certPath := filepath.Join(bundleDir, "client.crt")
	keyPath := filepath.Join(bundleDir, "client.key")
	caPath := filepath.Join(bundleDir, "ca-bundle.pem")

	enrollCli := controlplane.NewEnrollClient(srv.URL, "")
	enrollCli.HTTP = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 10 * time.Second}
	resp, err := enrollCli.Enroll(context.Background(), controlplane.EnrollRequest{AgentID: "agent-e2e", TTLSeconds: 3600})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := os.WriteFile(certPath, []byte(resp.CertPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(resp.KeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, []byte(resp.BundlePEM), 0o644); err != nil {
		t.Fatal(err)
	}

	originalCertBytes, _ := os.ReadFile(certPath)
	originalKeyBytes, _ := os.ReadFile(keyPath)

	tmpCertBlock, _ := pem.Decode(originalCertBytes)
	tmpCert, _ := x509.ParseCertificate(tmpCertBlock.Bytes)

	r := &controlplane.CertRenewer{
		AgentID:     "agent-e2e",
		CertPath:    certPath,
		KeyPath:     keyPath,
		CAPath:      caPath,
		Endpoint:    srv.URL,
		Insecure:    true,
		RenewBefore: 24 * time.Hour,
		Logger:      slog.Default(),
		TTLSeconds:  3600,
	}
	r.Tick(context.Background())

	rotatedCertBytes, _ := os.ReadFile(certPath)
	rotatedKeyBytes, _ := os.ReadFile(keyPath)
	if string(rotatedCertBytes) == string(originalCertBytes) {
		t.Fatal("cert was not rotated by renewer")
	}
	if string(rotatedKeyBytes) != string(originalKeyBytes) {
		t.Fatal("private key changed during renewal — CSR mode must keep the key intact")
	}
	rotatedCertBlock, _ := pem.Decode(rotatedCertBytes)
	rotatedCert, _ := x509.ParseCertificate(rotatedCertBlock.Bytes)
	if rotatedCert.SerialNumber.Cmp(tmpCert.SerialNumber) == 0 {
		t.Fatal("rotated cert has same serial as original")
	}

	if err := ca.Revoke(rotatedCert.SerialNumber.Text(16), "e2e revoke"); err != nil {
		t.Fatal(err)
	}
	beforeRevokeCert, _ := os.ReadFile(certPath)
	r.Tick(context.Background())
	afterRevokeCert, _ := os.ReadFile(certPath)
	if string(beforeRevokeCert) != string(afterRevokeCert) {
		t.Fatal("revoked cert was somehow renewed")
	}
}

func startTestCPServer(t *testing.T, ca *mca.CA, token string) *httptest.Server {
	t.Helper()
	enrollH := makeEnrollHandler(ca, token, nil, slog.Default())
	renewH := makeRenewHandler(ca, testTrustDomain, nil, slog.Default())

	srv := &controlplane.HTTPServer{
		EnrollHandle: enrollH,
		RenewHandle:  renewH,
		Token:        token,
	}

	tlsServer := httptest.NewUnstartedServer(srv.Handler())
	tlsServer.TLS = &tls.Config{
		ClientCAs:  ca.ClientCAPool(),
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS12,
	}
	tlsServer.StartTLS()
	t.Cleanup(func() { tlsServer.Close() })
	return tlsServer
}
