package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentTokens_HTTP_Create_RequiresOperator(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	srv.OperatorToken = "op-secret"

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/agent-tokens",
		bytes.NewReader([]byte(`{"name":"prod","description":"first"}`)))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without bearer, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/agent-tokens",
		bytes.NewReader([]byte(`{"name":"prod","description":"first"}`)))
	req.Header.Set("Authorization", "Bearer op-secret")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	var issued AgentTokenIssued
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if !strings.HasPrefix(issued.Token, agentTokenPrefix) {
		t.Fatalf("plaintext token prefix: %q", issued.Token)
	}
	if issued.ID == "" || issued.Name != "prod" {
		t.Fatalf("bad metadata: %+v", issued)
	}
}

func TestAgentTokens_HTTP_Create_RejectsEmptyName(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	srv.OperatorToken = "op"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/agent-tokens",
		bytes.NewReader([]byte(`{"name":"   "}`)))
	req.Header.Set("Authorization", "Bearer op")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestAgentTokens_HTTP_Create_RejectsBadJSON(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	srv.OperatorToken = "op"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/agent-tokens",
		bytes.NewReader([]byte(`{`)))
	req.Header.Set("Authorization", "Bearer op")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestAgentTokens_HTTP_List_HidesPlaintext(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	srv.OperatorToken = "op"
	if _, err := store.CreateAgentToken(context.Background(), "x", "", "op"); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/agent-tokens", nil)
	req.Header.Set("Authorization", "Bearer op")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), agentTokenPrefix) {
		t.Fatalf("plaintext token leaked in list response: %s", rec.Body.String())
	}
	var out []AgentToken
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out) != 1 {
		t.Fatalf("decode: %v len=%d", err, len(out))
	}
}

func TestAgentTokens_HTTP_List_IncludeRevoked(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	srv.OperatorToken = "op"
	tok1, err := store.CreateAgentToken(context.Background(), "live", "", "op")
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := store.CreateAgentToken(context.Background(), "dead", "", "op")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeAgentToken(context.Background(), tok2.ID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/agent-tokens", nil)
	req.Header.Set("Authorization", "Bearer op")
	srv.Handler().ServeHTTP(rec, req)
	var noRevoked []AgentToken
	_ = json.Unmarshal(rec.Body.Bytes(), &noRevoked)
	if len(noRevoked) != 1 || noRevoked[0].ID != tok1.ID {
		t.Errorf("default list should hide revoked: %+v", noRevoked)
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/v1/agent-tokens?include_revoked=1", nil)
	req2.Header.Set("Authorization", "Bearer op")
	srv.Handler().ServeHTTP(rec2, req2)
	var withRevoked []AgentToken
	_ = json.Unmarshal(rec2.Body.Bytes(), &withRevoked)
	if len(withRevoked) != 2 {
		t.Errorf("with include_revoked=1 should return 2, got %d", len(withRevoked))
	}
}

func TestAgentTokens_HTTP_Revoke(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	srv.OperatorToken = "op"
	issued, err := store.CreateAgentToken(context.Background(), "rotate-me", "", "op")
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/v1/agent-tokens/"+issued.ID, nil)
	req.Header.Set("Authorization", "Bearer op")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/v1/agent-tokens/"+issued.ID, nil)
	req.Header.Set("Authorization", "Bearer op")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on re-revoke, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/v1/agent-tokens/", nil)
	req.Header.Set("Authorization", "Bearer op")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing id should 400, got %d", rec.Code)
	}
}

func TestAgentTokens_HTTP_Item_MethodNotAllowed(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	srv.OperatorToken = "op"
	issued, _ := store.CreateAgentToken(context.Background(), "x", "", "op")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/agent-tokens/"+issued.ID, nil)
	req.Header.Set("Authorization", "Bearer op")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestAgentTokens_HTTP_Collection_MethodNotAllowed(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	srv.OperatorToken = "op"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/v1/agent-tokens", nil)
	req.Header.Set("Authorization", "Bearer op")
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestHTTPServer_OperatorBearer_FallsBackToLegacy(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	srv.Token = "legacy"
	srv.OperatorToken = ""
	if srv.operatorBearer() != "legacy" {
		t.Fatalf("empty operator token should fall back to legacy")
	}
	srv.OperatorToken = "operator"
	if srv.operatorBearer() != "operator" {
		t.Fatalf("non-empty operator token should win")
	}
}
