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
