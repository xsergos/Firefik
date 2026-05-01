package mca

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
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
