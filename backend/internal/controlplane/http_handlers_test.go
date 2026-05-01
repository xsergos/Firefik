package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestHTTPServer(t *testing.T) (*HTTPServer, Store) {
	t.Helper()
	store := NewMemoryStore()
	srv := &HTTPServer{
		Registry: NewRegistryWithStore(slog.New(slog.NewTextHandler(io.Discard, nil)), store),
		Token:    "secret",
	}
	return srv, store
}

func doReq(t *testing.T, h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestHTTP_Templates_RequireAuth(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rr := doReq(t, srv.Handler(), http.MethodGet, "/v1/templates", "", "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d", rr.Code)
	}
}

func TestHTTP_Templates_PublishAndGet(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	h := srv.Handler()
	body := `{"name":"deny-egress","body":"default: deny","labels":{"env":"prod"}}`
	rr := doReq(t, h, http.MethodPost, "/v1/templates", body, "secret")
	if rr.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", rr.Code, rr.Body.String())
	}
	var pub PolicyTemplate
	if err := json.Unmarshal(rr.Body.Bytes(), &pub); err != nil {
		t.Fatal(err)
	}
	if pub.Name != "deny-egress" || pub.Version != 1 {
		t.Errorf("got %+v", pub)
	}
	if pub.Publisher == "" {
		t.Error("publisher should be derived from token fingerprint")
	}

	rr = doReq(t, h, http.MethodGet, "/v1/templates/deny-egress", "", "secret")
	if rr.Code != http.StatusOK {
		t.Fatalf("get: %d", rr.Code)
	}
	rr = doReq(t, h, http.MethodGet, "/v1/templates/absent", "", "secret")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHTTP_Templates_RejectsMissingName(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rr := doReq(t, srv.Handler(), http.MethodPost, "/v1/templates", `{}`, "secret")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("code = %d", rr.Code)
	}
}

func TestHTTP_Templates_BadJSON(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rr := doReq(t, srv.Handler(), http.MethodPost, "/v1/templates", `not json`, "secret")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("code = %d", rr.Code)
	}
}

func TestHTTP_Templates_MethodNotAllowed(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rr := doReq(t, srv.Handler(), http.MethodDelete, "/v1/templates", "", "secret")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("code = %d", rr.Code)
	}
}

func TestHTTP_Approvals_FullFlow(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	h := srv.Handler()

	body := `{"policy_name":"p","proposed_body":"x","requester":"alice"}`
	rr := doReq(t, h, http.MethodPost, "/v1/approvals", body, "secret")
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var pa PendingApproval
	_ = json.Unmarshal(rr.Body.Bytes(), &pa)
	if pa.Status != ApprovalPending {
		t.Errorf("status = %s", pa.Status)
	}

	rr = doReq(t, h, http.MethodPost, "/v1/approvals/"+pa.ID+"/approve", `{"approver":"alice"}`, "secret")
	if rr.Code != http.StatusForbidden {
		t.Errorf("self-approve: %d", rr.Code)
	}

	if _, err := store.CreateApproval(context.Background(), PendingApproval{
		ID: "fixture", PolicyName: "p", ProposedBody: "y", Requester: "alice", RequesterFinger: "fp-a",
	}); err != nil {
		t.Fatal(err)
	}
	rr = doReq(t, h, http.MethodPost, "/v1/approvals/fixture/approve", `{"approver":"bob"}`, "secret")
	if rr.Code != http.StatusOK {
		t.Errorf("approve: %d %s", rr.Code, rr.Body.String())
	}

	rr = doReq(t, h, http.MethodGet, "/v1/approvals?status=pending", "", "secret")
	if rr.Code != http.StatusOK {
		t.Errorf("list: %d", rr.Code)
	}
	var list []PendingApproval
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	hasPending := false
	for _, a := range list {
		if a.Status == ApprovalPending {
			hasPending = true
		}
	}
	if !hasPending {
		t.Error("expected pending in list")
	}
}

func TestHTTP_Approvals_Reject(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	h := srv.Handler()
	if _, err := store.CreateApproval(context.Background(), PendingApproval{
		ID: "x", PolicyName: "p", ProposedBody: "b", Requester: "alice", RequesterFinger: "fp-a",
	}); err != nil {
		t.Fatal(err)
	}
	rr := doReq(t, h, http.MethodPost, "/v1/approvals/x/reject", `{"approver":"bob","comment":"nope"}`, "secret")
	if rr.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", rr.Code, rr.Body.String())
	}
	got, _ := store.GetApproval(context.Background(), "x")
	if got.Status != ApprovalRejected || got.RejectionComment != "nope" {
		t.Errorf("got %+v", got)
	}
}

func TestHTTP_Approvals_NotFound(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rr := doReq(t, srv.Handler(), http.MethodGet, "/v1/approvals/missing", "", "secret")
	if rr.Code != http.StatusNotFound {
		t.Errorf("code = %d", rr.Code)
	}
	rr = doReq(t, srv.Handler(), http.MethodPost, "/v1/approvals/missing/approve", `{}`, "secret")
	if rr.Code != http.StatusNotFound {
		t.Errorf("approve missing: %d", rr.Code)
	}
}

func TestHTTP_Approvals_NotPending(t *testing.T) {
	srv, store := newTestHTTPServer(t)
	if _, err := store.CreateApproval(context.Background(), PendingApproval{
		ID: "p1", PolicyName: "p", ProposedBody: "b", Requester: "alice", RequesterFinger: "fp-a",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApproveApproval(context.Background(), "p1", "bob", "fp-b"); err != nil {
		t.Fatal(err)
	}
	rr := doReq(t, srv.Handler(), http.MethodPost, "/v1/approvals/p1/approve", `{"approver":"carol"}`, "secret")
	if rr.Code != http.StatusConflict {
		t.Errorf("code = %d", rr.Code)
	}
}

func TestBearerFingerprint(t *testing.T) {
	if got := bearerFingerprint(""); got != "anonymous" {
		t.Errorf("empty = %q", got)
	}
	a := bearerFingerprint("secret")
	b := bearerFingerprint("secret")
	if a != b {
		t.Error("expected stable fingerprint")
	}
	if a == bearerFingerprint("other") {
		t.Error("expected different fingerprints")
	}
	if !strings.HasPrefix(a, "fp:") {
		t.Errorf("prefix: %s", a)
	}
}

func TestHTTP_Templates_NoStoreRoute(t *testing.T) {
	srv := &HTTPServer{}
	rr := doReq(t, srv.Handler(), http.MethodGet, "/v1/templates", "", "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 when no registry, got %d", rr.Code)
	}
}

func TestHTTP_Healthz(t *testing.T) {
	srv := &HTTPServer{}
	req := httptest.NewRequest(http.MethodGet, "/healthz", bytes.NewReader(nil))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "ok" {
		t.Errorf("got %d %q", rr.Code, rr.Body.String())
	}
}

func TestHTTP_Template_EmptyName(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rr := doReq(t, srv.Handler(), http.MethodGet, "/v1/templates/", "", "secret")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHTTP_Template_MethodNotAllowed(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rr := doReq(t, srv.Handler(), http.MethodDelete, "/v1/templates/foo", "", "secret")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("got %d", rr.Code)
	}
}

func TestHTTP_Approvals_BadJSON(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rr := doReq(t, srv.Handler(), http.MethodPost, "/v1/approvals", `not json`, "secret")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("got %d", rr.Code)
	}
}

func TestHTTP_Approvals_MethodNotAllowed(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rr := doReq(t, srv.Handler(), http.MethodDelete, "/v1/approvals", "", "secret")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("got %d", rr.Code)
	}
}

func TestHTTP_Approval_EmptyID(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rr := doReq(t, srv.Handler(), http.MethodGet, "/v1/approvals/", "", "secret")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("got %d", rr.Code)
	}
}

func TestHTTP_Approval_MethodNotAllowedOnAction(t *testing.T) {
	srv, _ := newTestHTTPServer(t)
	rr := doReq(t, srv.Handler(), http.MethodDelete, "/v1/approvals/x/approve", "", "secret")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("got %d", rr.Code)
	}
}

func TestCallerFingerprint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer mytoken")
	if got := callerFingerprint(req); got == "anonymous" || !strings.HasPrefix(got, "fp:") {
		t.Errorf("got %q", got)
	}
}

func TestCallerFingerprintAnonymous(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := callerFingerprint(req); got != "anonymous" {
		t.Errorf("got %q", got)
	}
}
