package mca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestInitAndIssue(t *testing.T) {
	dir := t.TempDir()
	ca, err := Init(dir, "spiffe://test.corp/")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	res, err := ca.Issue(IssueRequest{AgentID: "host-a"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(res.CertPEM) == 0 || len(res.KeyPEM) == 0 || len(res.BundlePEM) == 0 {
		t.Fatal("empty PEM output")
	}
	if !strings.HasPrefix(res.SPIFFEURI, "spiffe://test.corp/agent/host-a") {
		t.Errorf("SPIFFEURI = %q", res.SPIFFEURI)
	}

	ca2, err := Open(dir, "spiffe://test.corp/")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if ca2.rootCert.SerialNumber.Cmp(ca.rootCert.SerialNumber) != 0 {
		t.Error("reopened root serial differs")
	}
}

func TestVerifySPIFFEPeer(t *testing.T) {
	dir := t.TempDir()
	ca, err := Init(dir, "spiffe://prod.corp/")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	good, err := ca.Issue(IssueRequest{AgentID: "host-ok"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	verify := VerifySPIFFEPeer("spiffe://prod.corp/")

	cert := mustParseCert(t, good.CertPEM)
	if err := verify([][]byte{cert.Raw}, nil); err != nil {
		t.Fatalf("good cert rejected: %v", err)
	}

	other, err := Init(t.TempDir(), "spiffe://evil.corp/")
	if err != nil {
		t.Fatalf("init evil: %v", err)
	}
	bad, err := other.Issue(IssueRequest{AgentID: "intruder"})
	if err != nil {
		t.Fatalf("issue evil: %v", err)
	}
	badCert := mustParseCert(t, bad.CertPEM)
	if err := verify([][]byte{badCert.Raw}, nil); err == nil {
		t.Error("expected verify failure for foreign trust domain")
	}
}

func mustParseCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestIssueFromCSR(t *testing.T) {
	dir := t.TempDir()
	ca, err := Init(dir, "spiffe://test.corp/")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "host-csr"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	res, err := ca.IssueFromCSR(csrPEM, "host-csr", time.Hour)
	if err != nil {
		t.Fatalf("issue from csr: %v", err)
	}
	if len(res.KeyPEM) != 0 {
		t.Fatal("CSR-issued cert must NOT contain key material")
	}
	cert := mustParseCert(t, res.CertPEM)
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&priv.PublicKey) {
		t.Fatal("issued cert public key does not match CSR public key")
	}
}

func TestRevokeFlow(t *testing.T) {
	dir := t.TempDir()
	ca, err := Init(dir, "spiffe://test.corp/")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ca.Issue(IssueRequest{AgentID: "host", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if ca.IsRevoked(res.SerialHex) {
		t.Fatal("freshly issued cert reported as revoked")
	}
	if err := ca.Revoke(res.SerialHex, "compromised"); err != nil {
		t.Fatal(err)
	}
	if !ca.IsRevoked(res.SerialHex) {
		t.Fatal("revocation did not stick")
	}
	if !ca.IsRevoked(strings.ToUpper(res.SerialHex)) {
		t.Fatal("case-insensitive lookup failed")
	}

	ca2, err := Open(dir, "spiffe://test.corp/")
	if err != nil {
		t.Fatal(err)
	}
	if !ca2.IsRevoked(res.SerialHex) {
		t.Fatal("revocation not persisted across Open")
	}
	list := ca2.RevokedList()
	if len(list) != 1 || list[0].Reason != "compromised" {
		t.Fatalf("unexpected list: %+v", list)
	}
}

func TestIssueFromCSR_BadCSR(t *testing.T) {
	dir := t.TempDir()
	ca, err := Init(dir, "spiffe://test.corp/")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueFromCSR([]byte("not pem"), "host", time.Hour); err == nil {
		t.Fatal("expected error on non-PEM input")
	}
	if _, err := ca.IssueFromCSR([]byte("-----BEGIN CERTIFICATE REQUEST-----\nzzz\n-----END CERTIFICATE REQUEST-----\n"), "host", time.Hour); err == nil {
		t.Fatal("expected error on garbage CSR")
	}
}
