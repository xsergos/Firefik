package main

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"firefik/internal/controlplane"
)

func mdCtx(token string) context.Context {
	md := metadata.New(map[string]string{"authorization": "Bearer " + token})
	return metadata.NewIncomingContext(context.Background(), md)
}

func TestAuthenticateBearer_AcceptsLegacyToken(t *testing.T) {
	plaintext, err := authenticateBearer(mdCtx("legacy-secret"), "legacy-secret", nil)
	if err != nil {
		t.Fatalf("legacy token should authenticate: %v", err)
	}
	if plaintext != "legacy-secret" {
		t.Fatalf("plaintext propagation: %q", plaintext)
	}
}

func TestAuthenticateBearer_RejectsBadHeader(t *testing.T) {
	md := metadata.New(map[string]string{"authorization": "Token foo"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	_, err := authenticateBearer(ctx, "tok", nil)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("non-Bearer header should be Unauthenticated, got %v", err)
	}
}

func TestAuthenticateBearer_StoreBackedAgentTokenAccepted(t *testing.T) {
	store := controlplane.NewMemoryStore()
	issued, err := store.CreateAgentToken(context.Background(), "host-1", "", "ci")
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := authenticateBearer(mdCtx(issued.Token), "", store)
	if err != nil {
		t.Fatalf("store-backed token should authenticate: %v", err)
	}
	if plaintext != issued.Token {
		t.Fatalf("plaintext: %q want %q", plaintext, issued.Token)
	}
	// Touch persists last_used_at.
	out, _ := store.ListAgentTokens(context.Background(), false)
	if out[0].LastUsedAt == nil {
		t.Fatalf("expected last_used_at to be set after auth, got %+v", out[0])
	}
}

func TestAuthenticateBearer_RevokedAgentTokenRejected(t *testing.T) {
	store := controlplane.NewMemoryStore()
	issued, _ := store.CreateAgentToken(context.Background(), "host", "", "ci")
	_ = store.RevokeAgentToken(context.Background(), issued.ID)
	_, err := authenticateBearer(mdCtx(issued.Token), "", store)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked token must be Unauthenticated, got %v", err)
	}
}

func TestAuthenticateBearer_UnknownTokenRejected(t *testing.T) {
	store := controlplane.NewMemoryStore()
	_, err := authenticateBearer(mdCtx("agt_unknown"), "", store)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unknown token must be Unauthenticated, got %v", err)
	}
}

func TestAuthenticateBearer_NoAuthMode(t *testing.T) {
	// no legacy token AND no store → auth disabled (legacy "no auth required").
	_, err := authenticateBearer(mdCtx("anything"), "", nil)
	if err != nil {
		t.Fatalf("no-auth mode should accept any header: %v", err)
	}
	_, err = authenticateBearer(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("no-auth mode without metadata should accept: %v", err)
	}
}

func TestAuthenticateBearer_LegacyTokenOverridesStoreLookup(t *testing.T) {
	store := controlplane.NewMemoryStore()
	if _, err := authenticateBearer(mdCtx("legacy"), "legacy", store); err != nil {
		t.Fatalf("legacy token match should bypass store lookup: %v", err)
	}
}

func TestAuthenticateBearer_StoreFallbackThenReject(t *testing.T) {
	store := controlplane.NewMemoryStore()
	// Legacy is set; store has unrelated tokens; incoming neither matches legacy nor store.
	_, _ = store.CreateAgentToken(context.Background(), "x", "", "ci")
	_, err := authenticateBearer(mdCtx("agt_nope"), "legacy", store)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unmatched token with legacy+store must reject, got %v", err)
	}
	if !errors.Is(err, err) {
		t.Fatal("err should be non-nil")
	}
}

func TestUnaryAuth_StoreBackedAgentTokenFlowsThroughHandler(t *testing.T) {
	store := controlplane.NewMemoryStore()
	issued, _ := store.CreateAgentToken(context.Background(), "h", "", "ci")
	called := false
	handler := func(ctx context.Context, req any) (any, error) {
		called = true
		if v, _ := ctx.Value(struct{}{}).(any); v != nil {
			t.Fatal("unexpected value")
		}
		return "ok", nil
	}
	resp, err := unaryAuth("", store)(mdCtx(issued.Token), nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, handler)
	if err != nil || !called || resp != "ok" {
		t.Errorf("unaryAuth+store: err=%v called=%v resp=%v", err, called, resp)
	}
}

func TestStreamAuth_StoreBackedAgentTokenFlowsThroughHandler(t *testing.T) {
	store := controlplane.NewMemoryStore()
	issued, _ := store.CreateAgentToken(context.Background(), "h", "", "ci")
	called := false
	handler := grpc.StreamHandler(func(srv any, ss grpc.ServerStream) error { called = true; return nil })
	if err := streamAuth("", store)(nil, &fakeStream{ctx: mdCtx(issued.Token)}, &grpc.StreamServerInfo{}, handler); err != nil {
		t.Fatalf("streamAuth+store: %v", err)
	}
	if !called {
		t.Fatal("handler not called")
	}
}
