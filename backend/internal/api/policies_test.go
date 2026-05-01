package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"

	"firefik/internal/audit"
	"firefik/internal/config"
	"firefik/internal/docker"
	"firefik/internal/logstream"
	"firefik/internal/policy"
	"firefik/internal/rules"
)

func buildPolicyServer(t *testing.T, readonly bool, ctrs ...docker.ContainerInfo) (*Server, *httptest.Server) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		ChainName:        "FIREFIK",
		EffectiveChain:   "FIREFIK",
		ParentChain:      "DOCKER-USER",
		PoliciesReadOnly: readonly,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	reader := stubDocker{containers: ctrs}
	engine := rules.NewEngine(stubBackend{}, reader, cfg, logger)
	hub := logstream.NewHub(logger)
	traffic := NewTrafficStore()
	srv := NewServer(cfg, reader, engine, hub, logger, traffic)

	auditLogger := audit.New(logger)
	srv.SetAuditLogger(auditLogger)

	r := gin.New()
	srv.registerRoutes(r)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return srv, ts
}

func samplePolicy(t *testing.T, src string) *policy.Policy {
	t.Helper()
	pols, err := policy.Parse(src)
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}
	if len(pols) == 0 {
		t.Fatalf("no policies parsed")
	}
	pols[0].SourceBytes = []byte(src)
	return pols[0]
}

func doJSON(t *testing.T, ts *httptest.Server, method, path, body string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequestWithContext(context.Background(), method, ts.URL+path, reader)
	if err != nil {
		t.Fatalf("req: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func TestPolicyStore_EmptyListAndGet(t *testing.T) {
	s := NewPolicyStore()
	if list := s.List(); len(list) != 0 {
		t.Fatalf("expected empty list, got %d", len(list))
	}
	if _, ok := s.Get("missing"); ok {
		t.Fatalf("expected Get on empty store to be not-ok")
	}
}

func TestPolicyStore_SetReplacesEntireMap(t *testing.T) {
	s := NewPolicyStore()
	s.Upsert(&policy.Policy{Name: "old", Version: "v1"})
	s.Set(map[string]*policy.Policy{
		"a": {Name: "a", Version: "v1", Source: "f1"},
		"b": {Name: "b", Version: "v2"},
	})
	if _, ok := s.Get("old"); ok {
		t.Errorf("Set should replace: old still present")
	}
	list := s.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(list))
	}
	if list[0].Name != "a" || list[1].Name != "b" {
		t.Errorf("List must be sorted by name: %+v", list)
	}
}

func TestPolicyStore_UpsertAddsAndOverwrites(t *testing.T) {
	s := NewPolicyStore()
	s.Upsert(&policy.Policy{Name: "p", Version: "v1"})
	s.Upsert(&policy.Policy{Name: "p", Version: "v2"})
	got, ok := s.Get("p")
	if !ok {
		t.Fatalf("expected policy p")
	}
	if got.Version != "v2" {
		t.Errorf("Upsert must overwrite, got version %q", got.Version)
	}
	if len(s.List()) != 1 {
		t.Errorf("expected single entry after upsert")
	}
}

func TestPolicyStore_SetCopiesInputMap(t *testing.T) {
	s := NewPolicyStore()
	in := map[string]*policy.Policy{"x": {Name: "x"}}
	s.Set(in)
	delete(in, "x")
	if _, ok := s.Get("x"); !ok {
		t.Errorf("Set must defensively copy its input map")
	}
}

func TestHandleGetPolicies_EmptyStoreReturnsEmptyArray(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	status, body := doJSON(t, ts, http.MethodGet, "/api/policies", "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got []PolicySummary
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty list, got %+v", got)
	}
}

func TestHandleGetPolicies_ReturnsSummaries(t *testing.T) {
	srv, ts := buildPolicyServer(t, false)
	p := samplePolicy(t, `policy "web" { allow if proto == "tcp" and port == 80 }`)
	srv.Policies().Upsert(p)
	status, body := doJSON(t, ts, http.MethodGet, "/api/policies", "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got []PolicySummary
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 || got[0].Name != "web" {
		t.Errorf("unexpected: %+v", got)
	}
	if got[0].Rules != 1 {
		t.Errorf("expected 1 rule, got %d", got[0].Rules)
	}
}

func TestHandleValidatePolicy_InvalidBody(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	status, body := doJSON(t, ts, http.MethodPost, "/api/policies/validate", `{`)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got APIError
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Code != ErrCodeInvalidBody {
		t.Errorf("code=%q", got.Code)
	}
}

func TestHandleValidatePolicy_OK(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	payload := `{"dsl":"policy \"ok\" { allow if proto == \"tcp\" and port == 80 }"}`
	status, body := doJSON(t, ts, http.MethodPost, "/api/policies/validate", payload)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got policyValidateResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.OK {
		t.Errorf("expected OK=true, got %+v", got)
	}
}

func TestHandleValidatePolicy_ParseError(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	status, body := doJSON(t, ts, http.MethodPost, "/api/policies/validate",
		`{"dsl":"policy \"x\" { allow if"}`)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got policyValidateResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.OK || len(got.Errors) == 0 {
		t.Errorf("expected OK=false with errors, got %+v", got)
	}
}

func TestHandleValidatePolicy_CompileError(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	payload := `{"dsl":"policy \"bad\" { allow if port == \"not-a-number\" }"}`
	status, body := doJSON(t, ts, http.MethodPost, "/api/policies/validate", payload)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got policyValidateResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.OK {
		t.Errorf("expected OK=false from compile error: %+v", got)
	}
	if len(got.Errors) == 0 {
		t.Errorf("expected non-empty errors")
	}
}

func TestHandleGetPolicy_NotFound(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	status, body := doJSON(t, ts, http.MethodGet, "/api/policies/nope", "")
	if status != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got APIError
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Code != "policy_not_found" {
		t.Errorf("code=%q", got.Code)
	}
}

func TestHandleGetPolicy_ReturnsDetail(t *testing.T) {
	srv, ts := buildPolicyServer(t, false)
	p := samplePolicy(t, `policy "web" { allow if proto == "tcp" and port == 80 }`)
	srv.Policies().Upsert(p)

	status, body := doJSON(t, ts, http.MethodGet, "/api/policies/web", "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got PolicyDetail
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Name != "web" {
		t.Errorf("name=%q", got.Name)
	}
	if len(got.RuleSets) == 0 {
		t.Errorf("expected non-empty ruleSets")
	}
}

func TestHandleSimulatePolicy_WithInlineDSL(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	payload := `{"dsl":"policy \"sim\" { allow if proto == \"tcp\" and port == 22 }"}`
	status, body := doJSON(t, ts, http.MethodPost, "/api/policies/sim/simulate", payload)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got PolicySimulateResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Policy != "sim" {
		t.Errorf("policy=%q", got.Policy)
	}
	if len(got.RuleSets) == 0 {
		t.Errorf("expected ruleSets from inline DSL")
	}
}

func TestHandleSimulatePolicy_DSLParseError(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	payload := `{"dsl":"policy \"broken\" { allow"}`
	status, body := doJSON(t, ts, http.MethodPost, "/api/policies/broken/simulate", payload)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got PolicySimulateResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Errors) == 0 {
		t.Errorf("expected errors, got %+v", got)
	}
}

func TestHandleSimulatePolicy_DSLFallbackFirstPolicy(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	payload := `{"dsl":"policy \"mismatch\" { allow if port == 9000 }"}`
	status, body := doJSON(t, ts, http.MethodPost, "/api/policies/requested/simulate", payload)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got PolicySimulateResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Policy != "mismatch" {
		t.Errorf("expected fallback to first policy, got %q", got.Policy)
	}
}

func TestHandleSimulatePolicy_CompileError(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	payload := `{"dsl":"policy \"broken\" { allow if port == \"str\" }"}`
	status, body := doJSON(t, ts, http.MethodPost, "/api/policies/broken/simulate", payload)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got PolicySimulateResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Errors) == 0 {
		t.Errorf("expected compile error: %+v", got)
	}
}

func TestHandleSimulatePolicy_ExistingPolicy(t *testing.T) {
	srv, ts := buildPolicyServer(t, false)
	srv.Policies().Upsert(samplePolicy(t, `policy "existing" { allow if port == 443 }`))

	status, body := doJSON(t, ts, http.MethodPost, "/api/policies/existing/simulate", ``)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got PolicySimulateResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Policy != "existing" {
		t.Errorf("policy=%q", got.Policy)
	}
	if len(got.RuleSets) == 0 {
		t.Errorf("expected ruleSets")
	}
}

func TestHandleSimulatePolicy_ExistingNotFound(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	status, body := doJSON(t, ts, http.MethodPost, "/api/policies/nope/simulate", ``)
	if status != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got APIError
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Code != "policy_not_found" {
		t.Errorf("code=%q", got.Code)
	}
}

func TestHandleSimulatePolicy_WithContainer(t *testing.T) {
	ctr := docker.ContainerInfo{
		ID:     "abcdef012345000000000000000000000000000000000000000000000000aaaa",
		Name:   "app",
		Status: "running",
		Labels: map[string]string{"firefik.enabled": "true"},
	}
	srv, ts := buildPolicyServer(t, false, ctr)
	srv.Policies().Upsert(samplePolicy(t, `policy "container-bound" { allow if port == 9090 }`))

	payload := `{"containerID":"abcdef012345000000000000000000000000000000000000000000000000aaaa"}`
	status, body := doJSON(t, ts, http.MethodPost, "/api/policies/container-bound/simulate", payload)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got PolicySimulateResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Container == "" {
		t.Errorf("expected container id in response, got %+v", got)
	}
	if got.LabelsSeen[rules.PolicyLabel] != "container-bound" {
		t.Errorf("expected PolicyLabel to be injected when missing, got %v", got.LabelsSeen)
	}
}

func TestHandleWritePolicy_ReadOnlyRejected(t *testing.T) {
	_, ts := buildPolicyServer(t, true)
	payload := `{"dsl":"policy \"ro\" { allow if port == 80 }"}`
	status, body := doJSON(t, ts, http.MethodPut, "/api/policies/ro", payload)
	if status != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got APIError
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Code != "policies_readonly" {
		t.Errorf("code=%q", got.Code)
	}
}

func TestHandleWritePolicy_InvalidName(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	payload := `{"dsl":"policy \"x\" { allow if port == 80 }"}`
	status, body := doJSON(t, ts, http.MethodPut, "/api/policies/bad%20name", payload)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got APIError
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Code != "invalid_name" {
		t.Errorf("code=%q", got.Code)
	}
}

func TestHandleWritePolicy_InvalidBody(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	status, body := doJSON(t, ts, http.MethodPut, "/api/policies/ok", `{`)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got APIError
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Code != ErrCodeInvalidBody {
		t.Errorf("code=%q", got.Code)
	}
}

func TestHandleWritePolicy_ParseError(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	payload := `{"dsl":"policy \"ok\" { allow"}`
	status, body := doJSON(t, ts, http.MethodPut, "/api/policies/ok", payload)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got APIError
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Code != "policy_parse_failed" {
		t.Errorf("code=%q", got.Code)
	}
}

func TestHandleWritePolicy_NameMismatch(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	payload := `{"dsl":"policy \"one\" { allow if port == 80 } policy \"two\" { allow if port == 81 }"}`
	status, body := doJSON(t, ts, http.MethodPut, "/api/policies/three", payload)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got APIError
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Code != "policy_name_mismatch" {
		t.Errorf("code=%q", got.Code)
	}
}

func TestHandleWritePolicy_CompileError(t *testing.T) {
	_, ts := buildPolicyServer(t, false)
	payload := `{"dsl":"policy \"ok\" { allow if port == \"str\" }"}`
	status, body := doJSON(t, ts, http.MethodPut, "/api/policies/ok", payload)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got APIError
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Code != "policy_compile_failed" {
		t.Errorf("code=%q", got.Code)
	}
}

func TestHandleWritePolicy_SuccessSingle(t *testing.T) {
	srv, ts := buildPolicyServer(t, false)
	payload := `{"dsl":"policy \"ok\" { allow if proto == \"tcp\" and port == 80 }","comment":"initial"}`
	status, body := doJSON(t, ts, http.MethodPut, "/api/policies/ok", payload)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got PolicySummary
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Name != "ok" || got.Source != "api" || got.Rules != 1 {
		t.Errorf("unexpected summary: %+v", got)
	}
	if _, ok := srv.Policies().Get("ok"); !ok {
		t.Errorf("policy not stored")
	}
}

func TestHandleWritePolicy_PicksMatchingFromMultiple(t *testing.T) {
	srv, ts := buildPolicyServer(t, false)
	payload := `{"dsl":"policy \"one\" { allow if port == 80 } policy \"two\" { allow if port == 81 }"}`
	status, body := doJSON(t, ts, http.MethodPut, "/api/policies/two", payload)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got PolicySummary
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Name != "two" {
		t.Errorf("wrong policy chosen: %+v", got)
	}
	if _, ok := srv.Policies().Get("two"); !ok {
		t.Errorf("policy not stored under correct name")
	}
}
