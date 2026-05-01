package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"

	"firefik/internal/config"
	"firefik/internal/docker"
	"firefik/internal/logstream"
	"firefik/internal/rules"
)

type stubDocker struct {
	containers []docker.ContainerInfo
}

func (s stubDocker) ListContainers(ctx context.Context) ([]docker.ContainerInfo, error) {
	return s.containers, nil
}

func (s stubDocker) Inspect(ctx context.Context, id string) (docker.ContainerInfo, bool, error) {
	for _, c := range s.containers {
		if c.ID == id {
			return c, true, nil
		}
	}
	return docker.ContainerInfo{}, false, nil
}

type stubBackend struct{}

func (stubBackend) SetupChains() error { return nil }
func (stubBackend) Cleanup() error     { return nil }
func (stubBackend) ApplyContainerRules(string, string, []net.IP, []docker.FirewallRuleSet, string, []net.IPNet) error {
	return nil
}
func (stubBackend) RemoveContainerChains(string) error         { return nil }
func (stubBackend) ListAppliedContainerIDs() ([]string, error) { return nil, nil }
func (stubBackend) Healthy() (rules.HealthReport, error)       { return rules.HealthReport{}, nil }

func buildContractServer(t *testing.T) *httptest.Server {
	t.Helper()

	gin.SetMode(gin.TestMode)

	ctr := docker.ContainerInfo{
		ID:     "abcdef012345000000000000000000000000000000000000000000000000aaaa",
		Name:   "nginx",
		Status: "running",
		Labels: map[string]string{"firefik.enabled": "true"},
	}
	cfg := &config.Config{
		ChainName:      "FIREFIK",
		EffectiveChain: "FIREFIK",
		ParentChain:    "DOCKER-USER",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	reader := stubDocker{containers: []docker.ContainerInfo{ctr}}
	engine := rules.NewEngine(stubBackend{}, reader, cfg, logger)
	hub := logstream.NewHub(logger)
	traffic := NewTrafficStore()
	srv := NewServer(cfg, reader, engine, hub, logger, traffic)

	r := gin.New()
	srv.registerRoutes(r)

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return ts
}

func doGET(t *testing.T, ts *httptest.Server, path string) (int, []byte) {
	t.Helper()
	resp, err := ts.Client().Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func doPOST(t *testing.T, ts *httptest.Server, path string) (int, []byte) {
	t.Helper()
	resp, err := ts.Client().Post(ts.URL+path, "application/json", bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func TestContract_Health_StatusResponse(t *testing.T) {
	ts := buildContractServer(t)
	status, body := doGET(t, ts, "/health")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got StatusResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal StatusResponse: %v\nbody: %s", err, body)
	}
	if got.Status != "ok" {
		t.Errorf("status=%q", got.Status)
	}
}

func TestContract_Containers_ListDTO(t *testing.T) {
	ts := buildContractServer(t)
	status, body := doGET(t, ts, "/api/containers")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got []ContainerDTO
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal []ContainerDTO: %v\nbody: %s", err, body)
	}
	if len(got) != 1 || got[0].Name != "nginx" {
		t.Errorf("unexpected payload: %+v", got)
	}
}

func TestContract_Container_SingleDTO(t *testing.T) {
	ts := buildContractServer(t)
	status, body := doGET(t, ts, "/api/containers/abcdef012345000000000000000000000000000000000000000000000000aaaa")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got ContainerDTO
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal ContainerDTO: %v", err)
	}
	if got.Name != "nginx" {
		t.Errorf("got name=%q", got.Name)
	}
}

func TestContract_Container_NotFound_ReturnsAPIError(t *testing.T) {
	ts := buildContractServer(t)
	status, body := doGET(t, ts, "/api/containers/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if status != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got APIError
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal APIError: %v", err)
	}
	if got.Code != ErrCodeContainerMissing {
		t.Errorf("code=%q", got.Code)
	}
}

func TestContract_Container_InvalidID_ReturnsAPIError(t *testing.T) {
	ts := buildContractServer(t)
	status, body := doGET(t, ts, "/api/containers/not-a-hex-id")
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got APIError
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal APIError: %v", err)
	}
	if got.Code != ErrCodeInvalidID {
		t.Errorf("code=%q", got.Code)
	}
}

func TestContract_Rules_ListEntries(t *testing.T) {
	ts := buildContractServer(t)
	status, body := doGET(t, ts, "/api/rules")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got []RuleEntry
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal []RuleEntry: %v", err)
	}
}

func TestContract_Profiles_ListEntries(t *testing.T) {
	ts := buildContractServer(t)
	status, body := doGET(t, ts, "/api/rules/profiles")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got []ProfileEntry
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal []ProfileEntry: %v", err)
	}
	if len(got) == 0 {
		t.Errorf("expected at least one profile, got 0")
	}
}

func TestContract_Stats_Shape(t *testing.T) {
	ts := buildContractServer(t)
	status, body := doGET(t, ts, "/api/stats")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got StatsResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal StatsResponse: %v", err)
	}
	if got.Containers.Total != 1 {
		t.Errorf("total=%d", got.Containers.Total)
	}
}

func TestContract_Apply_StatusResponse(t *testing.T) {
	ts := buildContractServer(t)
	status, body := doPOST(t, ts, "/api/containers/abcdef012345000000000000000000000000000000000000000000000000aaaa/apply")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got StatusResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal StatusResponse: %v", err)
	}
	if got.Status != "applied" {
		t.Errorf("status=%q", got.Status)
	}
}

func TestContract_Disable_StatusResponse(t *testing.T) {
	ts := buildContractServer(t)
	status, body := doPOST(t, ts, "/api/containers/abcdef012345000000000000000000000000000000000000000000000000aaaa/disable")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var got StatusResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal StatusResponse: %v", err)
	}
	if got.Status != "disabled" {
		t.Errorf("status=%q", got.Status)
	}
}

func TestContract_OpenAPI_JSON(t *testing.T) {
	ts := buildContractServer(t)
	status, body := doGET(t, ts, "/api/v1/openapi.json")
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	var spec map[string]any
	if err := json.Unmarshal(body, &spec); err != nil {
		t.Fatalf("unmarshal swagger.json: %v", err)
	}
	if spec["swagger"] != "2.0" {
		t.Errorf("expected swagger=2.0, got %v", spec["swagger"])
	}
	info, _ := spec["info"].(map[string]any)
	if info["title"] != "Firefik API" {
		t.Errorf("title=%v", info["title"])
	}
	paths, _ := spec["paths"].(map[string]any)
	wantPaths := []string{
		"/api/containers",
		"/api/containers/{id}",
		"/api/containers/{id}/apply",
		"/api/containers/{id}/disable",
		"/api/rules",
		"/api/rules/profiles",
		"/api/stats",
		"/api/v1/openapi.json",
		"/api/v1/openapi.yaml",
		"/health",
		"/ready",
		"/ws/logs",
	}
	for _, p := range wantPaths {
		if _, ok := paths[p]; !ok {
			t.Errorf("path %q missing from spec", p)
		}
	}
}

func TestContract_OpenAPI_YAML(t *testing.T) {
	ts := buildContractServer(t)
	status, body := doGET(t, ts, "/api/v1/openapi.yaml")
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	if !bytes.Contains(body, []byte("swagger:")) && !bytes.Contains(body, []byte("openapi:")) {
		t.Errorf("yaml spec missing swagger/openapi marker:\n%s", body)
	}
}
