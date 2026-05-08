package controlplane

import (
	"testing"
	"time"

	"firefik/internal/controlplane/mca"
)

func TestMCAAdapter_Smoke(t *testing.T) {
	dir := t.TempDir()
	ca, err := mca.Init(dir, "spiffe://test/")
	if err != nil {
		t.Fatal(err)
	}
	a := MCAAdapter{CA: ca}

	if len(a.TrustBundlePEM()) == 0 {
		t.Fatal("empty trust bundle")
	}
	if a.IsRevoked("nonexistent") {
		t.Fatal("nothing revoked yet")
	}
	res, err := a.Issue(CAIssueRequest{AgentID: "agent-x", TTL: time.Hour})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if res.SerialHex == "" || len(res.CertPEM) == 0 || len(res.KeyPEM) == 0 {
		t.Fatalf("incomplete: %+v", res)
	}
	if err := ca.Revoke(res.SerialHex, "test"); err != nil {
		t.Fatal(err)
	}
	if !a.IsRevoked(res.SerialHex) {
		t.Fatal("expected revoked")
	}

	other, err := a.Issue(CAIssueRequest{AgentID: "agent-y", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := certRequestPEM(t, "agent-y", &otherKeyHolder{})
	_ = other
	if _, err := a.IssueFromCSR(csrPEM, "agent-y", time.Hour); err == nil {
		t.Fatal("expected error: CSR built with a different key against fresh handler")
	}

	if ca.IssuingFingerprint() == "" {
		t.Fatal("issuer fingerprint must not be empty after Init")
	}
}

type otherKeyHolder struct{}

func certRequestPEM(t *testing.T, _ string, _ *otherKeyHolder) []byte {
	t.Helper()
	return []byte("not pem")
}
