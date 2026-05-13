package controlplane

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

func newAgentTokenSQLiteStore(t *testing.T) Store {
	t.Helper()
	s, err := NewSQLiteStore(context.Background(), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAgentTokens_MemoryStore_CreateListRevokeValidate(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	issued, err := s.CreateAgentToken(ctx, "ci-host", "issued for integration tests", "operator-x")
	if err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}
	if issued.Token == "" || !looksLikeAgentToken(issued.Token) {
		t.Fatalf("plaintext token format: %q", issued.Token)
	}
	if issued.ID == "" || issued.Name != "ci-host" || issued.IssuedBy != "operator-x" {
		t.Fatalf("bad metadata: %+v", issued)
	}

	out, err := s.ListAgentTokens(ctx, false)
	if err != nil || len(out) != 1 || out[0].ID != issued.ID {
		t.Fatalf("ListAgentTokens: %+v err=%v", out, err)
	}

	got, err := s.ValidateAgentToken(ctx, issued.Token)
	if err != nil || got.ID != issued.ID {
		t.Fatalf("ValidateAgentToken: %+v err=%v", got, err)
	}

	if _, err := s.ValidateAgentToken(ctx, "agt_bogus"); !errors.Is(err, ErrAgentTokenUnknown) {
		t.Fatalf("unknown token should err Unknown, got %v", err)
	}

	if err := s.TouchAgentToken(ctx, issued.ID, "10.0.0.5"); err != nil {
		t.Fatalf("TouchAgentToken: %v", err)
	}
	out, _ = s.ListAgentTokens(ctx, false)
	if out[0].LastUsedAt == nil || out[0].LastUsedIP != "10.0.0.5" {
		t.Fatalf("touch did not update: %+v", out[0])
	}

	if err := s.RevokeAgentToken(ctx, issued.ID); err != nil {
		t.Fatalf("RevokeAgentToken: %v", err)
	}
	if _, err := s.ValidateAgentToken(ctx, issued.Token); !errors.Is(err, ErrAgentTokenRevoked) {
		t.Fatalf("revoked token should err Revoked, got %v", err)
	}
	if err := s.RevokeAgentToken(ctx, issued.ID); !errors.Is(err, ErrAgentTokenUnknown) {
		t.Fatalf("re-revoke should err Unknown, got %v", err)
	}

	out, _ = s.ListAgentTokens(ctx, false)
	if len(out) != 0 {
		t.Fatalf("ListAgentTokens(includeRevoked=false) should hide revoked, got %d", len(out))
	}
	out, _ = s.ListAgentTokens(ctx, true)
	if len(out) != 1 {
		t.Fatalf("ListAgentTokens(includeRevoked=true) should return revoked, got %d", len(out))
	}
}

func TestAgentTokens_MemoryStore_EmptyNameRejected(t *testing.T) {
	if _, err := NewMemoryStore().CreateAgentToken(context.Background(), "   ", "", ""); err == nil {
		t.Fatal("empty name should error")
	}
}

func TestAgentTokens_MemoryStore_ValidateEmpty(t *testing.T) {
	if _, err := NewMemoryStore().ValidateAgentToken(context.Background(), ""); !errors.Is(err, ErrAgentTokenUnknown) {
		t.Fatal("empty plaintext should err Unknown")
	}
}

func TestAgentTokens_SQLite_FullCycle(t *testing.T) {
	s := newAgentTokenSQLiteStore(t)
	ctx := context.Background()

	issued, err := s.CreateAgentToken(ctx, "prod-1", "primary", "operator-y")
	if err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}
	out, err := s.ListAgentTokens(ctx, false)
	if err != nil || len(out) != 1 || out[0].Name != "prod-1" {
		t.Fatalf("ListAgentTokens: %+v err=%v", out, err)
	}
	got, ok, err := s.GetAgentToken(ctx, issued.ID)
	if err != nil || !ok || got.ID != issued.ID {
		t.Fatalf("GetAgentToken: %+v ok=%v err=%v", got, ok, err)
	}
	if _, err := s.ValidateAgentToken(ctx, issued.Token); err != nil {
		t.Fatalf("ValidateAgentToken: %v", err)
	}
	if err := s.TouchAgentToken(ctx, issued.ID, "10.0.0.7"); err != nil {
		t.Fatalf("TouchAgentToken: %v", err)
	}
	got, _, _ = s.GetAgentToken(ctx, issued.ID)
	if got.LastUsedAt == nil || got.LastUsedIP != "10.0.0.7" {
		t.Fatalf("touch persisted? %+v", got)
	}
	if err := s.RevokeAgentToken(ctx, issued.ID); err != nil {
		t.Fatalf("RevokeAgentToken: %v", err)
	}
	if _, err := s.ValidateAgentToken(ctx, issued.Token); !errors.Is(err, ErrAgentTokenRevoked) {
		t.Fatalf("revoked SQLite token should err Revoked, got %v", err)
	}
}

func TestAgentTokens_GetAgentToken_MissingReturnsFalse(t *testing.T) {
	s := NewMemoryStore()
	got, ok, err := s.GetAgentToken(context.Background(), "nope")
	if err != nil || ok || got.ID != "" {
		t.Fatalf("missing should be (zero,false,nil), got %+v ok=%v err=%v", got, ok, err)
	}
}
