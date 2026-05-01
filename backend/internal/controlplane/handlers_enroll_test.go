package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHTTP_EnrollmentTokens_RequireAuth(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/enrollment-tokens", `{"agent_id":"host-a"}`, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d want 401", rec.Code)
	}
}

func TestHTTP_EnrollmentTokens_CreateValidatesAgentID(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	cases := []string{"AB", "Host", "agent_id_with_underscore", "x", "ok!"}
	for _, bad := range cases {
		body := `{"agent_id":"` + bad + `"}`
		rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/enrollment-tokens", body, "secret")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("agent_id=%q got %d want 400 body=%s", bad, rec.Code, rec.Body.String())
		}
	}
}

func TestHTTP_EnrollmentTokens_CreateAcceptsValidAgentID(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	body := `{"agent_id":"host-prod-01","ttl_seconds":600}`
	rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/enrollment-tokens", body, "secret")
	if rec.Code != http.StatusCreated {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp createEnrollmentTokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" || resp.AgentID != "host-prod-01" {
		t.Fatalf("bad response: %+v", resp)
	}
	if resp.ExpiresAt.Before(time.Now()) {
		t.Fatalf("expires_at in past: %v", resp.ExpiresAt)
	}
	tokens, err := store.ListEnrollmentTokens(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 || tokens[0].Token != resp.Token {
		t.Fatalf("token not stored: %+v", tokens)
	}
}

func TestHTTP_EnrollmentTokens_ListDefaults(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	now := time.Now().UTC()
	if err := store.CreateEnrollmentToken(context.Background(), EnrollmentToken{
		Token: "abc", AgentID: "h1", TTLSeconds: 60, ExpiresAt: now.Add(time.Minute), IssuedBy: "test", IssuedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	used := now
	if err := store.CreateEnrollmentToken(context.Background(), EnrollmentToken{
		Token: "xyz", AgentID: "h2", TTLSeconds: 60, ExpiresAt: now.Add(time.Minute), IssuedBy: "test", IssuedAt: now, ConsumedAt: &used,
	}); err != nil {
		t.Fatal(err)
	}

	rec := doReq(t, srv.Handler(), http.MethodGet, "/v1/enrollment-tokens", "", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	var out []EnrollmentToken
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, et := range out {
		if et.Token == "xyz" {
			t.Fatalf("used token leaked into default list: %+v", et)
		}
	}

	rec = doReq(t, srv.Handler(), http.MethodGet, "/v1/enrollment-tokens?include_used=1", "", "secret")
	body := rec.Body.String()
	if !strings.Contains(body, "abc") || !strings.Contains(body, "xyz") {
		t.Fatalf("include_used=1 should return both: %s", body)
	}
}

func TestStore_EnrollmentToken_ConsumeFlow(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now().UTC()
	tk := EnrollmentToken{
		Token:      "tok-1",
		AgentID:    "host-a",
		TTLSeconds: 600,
		ExpiresAt:  now.Add(10 * time.Minute),
		IssuedBy:   "op",
		IssuedAt:   now,
	}
	if err := store.CreateEnrollmentToken(context.Background(), tk); err != nil {
		t.Fatal(err)
	}
	out, err := store.ConsumeEnrollmentToken(context.Background(), "tok-1", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if out.ConsumedAt == nil || out.ConsumerIP != "10.0.0.1" {
		t.Fatalf("consume not recorded: %+v", out)
	}
	if _, err := store.ConsumeEnrollmentToken(context.Background(), "tok-1", "10.0.0.2"); err == nil {
		t.Fatal("second consume should fail")
	}
}

func TestStore_EnrollmentToken_ExpiredRejected(t *testing.T) {
	store := NewMemoryStore()
	past := time.Now().UTC().Add(-time.Hour)
	if err := store.CreateEnrollmentToken(context.Background(), EnrollmentToken{
		Token:     "exp-1",
		AgentID:   "host-a",
		ExpiresAt: past,
		IssuedAt:  past.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeEnrollmentToken(context.Background(), "exp-1", ""); err == nil {
		t.Fatal("expected error for expired")
	}
}

func TestStore_EnrollmentToken_RevokeBlocksConsume(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now().UTC()
	if err := store.CreateEnrollmentToken(context.Background(), EnrollmentToken{
		Token:     "rev-1",
		AgentID:   "host-a",
		ExpiresAt: now.Add(time.Hour),
		IssuedAt:  now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeEnrollmentToken(context.Background(), "rev-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeEnrollmentToken(context.Background(), "rev-1", ""); err == nil {
		t.Fatal("expected revoked rejection")
	}
}

func TestHTTP_EnrollmentTokens_TTLExceedsMax(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	body := `{"agent_id":"host-a","ttl_seconds":99999999}`
	rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/enrollment-tokens", body, "secret")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_EnrollmentTokens_InvalidJSON(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/enrollment-tokens", `{not-json`, "secret")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_EnrollmentTokens_DefaultTTLApplied(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	body := `{"agent_id":"host-a"}`
	rec := doReq(t, srv.Handler(), http.MethodPost, "/v1/enrollment-tokens", body, "secret")
	if rec.Code != http.StatusCreated {
		t.Fatalf("got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp createEnrollmentTokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	want := defaultTokenTTL
	got := resp.ExpiresAt.Sub(resp.IssuedAt)
	if delta := got - want; delta < -time.Second || delta > time.Second {
		t.Fatalf("default TTL not applied: got %v want %v", got, want)
	}
}

func TestHTTP_EnrollmentTokens_MethodNotAllowed(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rec := doReq(t, srv.Handler(), http.MethodPut, "/v1/enrollment-tokens", `{"agent_id":"host-a"}`, "secret")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d want 405", rec.Code)
	}
}

func TestHTTP_EnrollmentTokens_ListEmptyReturnsArray(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rec := doReq(t, srv.Handler(), http.MethodGet, "/v1/enrollment-tokens", "", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "[]" {
		t.Fatalf("expected '[]', got %q", body)
	}
}

func TestParseCommandAction_AllVariants(t *testing.T) {
	cases := map[string]CommandKind{
		"apply":        CommandApply,
		"APPLY":        CommandApply,
		"disable":      CommandDisable,
		"reconcile":    CommandReconcile,
		"token_rotate": CommandTokenRotate,
		"token-rotate": CommandTokenRotate,
		"Token-Rotate": CommandTokenRotate,
	}
	for input, want := range cases {
		got, err := parseCommandAction(input)
		if err != nil {
			t.Errorf("%q: unexpected error %v", input, err)
		}
		if got != want {
			t.Errorf("%q: got %v want %v", input, got, want)
		}
	}
	if _, err := parseCommandAction(""); err == nil {
		t.Errorf("empty action should fail")
	}
	if _, err := parseCommandAction("unknown"); err == nil {
		t.Errorf("unknown action should fail")
	}
}

func TestValidInstanceID(t *testing.T) {
	cases := []struct {
		id string
		ok bool
	}{
		{"host-prod-01", true},
		{"abc", true},
		{"a", false},
		{"AB", false},
		{strings.Repeat("a", 64), false},
		{strings.Repeat("a", 63), true},
		{"hi.world", false},
		{"hi_world", false},
		{"hello!", false},
	}
	for _, c := range cases {
		if got := validInstanceID(c.id); got != c.ok {
			t.Errorf("id=%q got=%v want=%v", c.id, got, c.ok)
		}
	}
}
