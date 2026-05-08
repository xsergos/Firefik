package mca

import (
	"testing"
)

func TestClientCAPool(t *testing.T) {
	dir := t.TempDir()
	ca, err := Init(dir, "spiffe://test/")
	if err != nil {
		t.Fatal(err)
	}
	pool := ca.ClientCAPool()
	if pool == nil {
		t.Errorf("nil pool")
	}
}

func TestRootAndIssuingCert(t *testing.T) {
	dir := t.TempDir()
	ca, err := Init(dir, "spiffe://test/")
	if err != nil {
		t.Fatal(err)
	}
	if ca.RootCert() == nil {
		t.Errorf("nil root")
	}
	if ca.IssuingCert() == nil {
		t.Errorf("nil issuing")
	}
}

func TestInitEmptyTrustDomain(t *testing.T) {
	_, _ = Init(t.TempDir(), "")
}

func TestOpenMissingDir(t *testing.T) {
	if _, err := Open("/nonexistent/dir", "spiffe://test/"); err == nil {
		t.Errorf("expected error")
	}
}

func TestIssuingFingerprint(t *testing.T) {
	dir := t.TempDir()
	ca, err := Init(dir, "spiffe://t.firefik/")
	if err != nil {
		t.Fatal(err)
	}
	fp := ca.IssuingFingerprint()
	if fp == "" {
		t.Fatal("expected non-empty issuing fingerprint")
	}
	for _, c := range fp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("expected hex, got %q", fp)
		}
	}

	empty := &CA{}
	if got := empty.IssuingFingerprint(); got != "" {
		t.Fatalf("empty CA: expected empty, got %q", got)
	}
}

func TestIssueEmptyAgent(t *testing.T) {
	dir := t.TempDir()
	ca, err := Init(dir, "spiffe://test/")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Issue(IssueRequest{}); err == nil {
		t.Errorf("expected error for empty agent")
	}
}
