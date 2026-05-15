package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"firefik/internal/audit"
	"firefik/internal/config"
	"firefik/internal/docker"
	"firefik/internal/logstream"
	"firefik/internal/rules"
)

func websocketDial(t *testing.T, url string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	d := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	return d.Dial(url, nil)
}

func TestHandleBulkContainersBadJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.POST("/b", s.handleBulkContainers)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/b", strings.NewReader(`{`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestHandleBulkContainersUnknownContainer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.POST("/b", s.handleBulkContainers)
	body := `{"actions":[{"id":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","action":"apply"}]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/b", strings.NewReader(body))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "error") {
		t.Errorf("expected error in response: %s", rec.Body.String())
	}
}

func TestHandleBulkContainersDisableInvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.POST("/b", s.handleBulkContainers)
	body := `{"actions":[{"id":"not-hex","action":"disable"}]}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/b", strings.NewReader(body))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleGetTemplates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	s.templates.Set(map[string]config.RuleTemplate{
		"web": {Name: "web"},
	})
	r := gin.New()
	r.GET("/t", s.handleGetTemplates)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/t", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "web") {
		t.Errorf("missing template: %s", rec.Body.String())
	}
}

func TestHandleGetAuditHistoryNoBuffer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.GET("/a", s.handleGetAuditHistory)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/a", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestHandleGetAuditHistoryWithBuffer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	hb := audit.NewHistoryBuffer(5)
	hb.Write(audit.Event{Action: "apply"})
	s.SetHistory(hb)
	r := gin.New()
	r.GET("/a", s.handleGetAuditHistory)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/a", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestHandleWSLogsRejectsRegularGET(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.GET("/ws/logs", s.handleWSLogs)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ws/logs", nil)
	r.ServeHTTP(rec, req)
}

func TestHandleWSLogsTooManyClients(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{WSMaxSubscribers: 1}
	s := makeTestServer(t, cfg)
	if !s.wsCounter.admit("127.0.0.1") {
		t.Fatal("first admit should succeed")
	}
	r := gin.New()
	r.GET("/ws/logs", s.handleWSLogs)
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/ws/logs")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("code=%d", resp.StatusCode)
	}
}

func TestHandleWSLogsUpgradeAndStream(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)

	hubCtx, hubCancel := context.WithCancel(context.Background())
	defer hubCancel()
	go s.hub.Run(hubCtx)

	r := gin.New()
	r.GET("/ws/logs", s.handleWSLogs)
	ts := httptest.NewServer(r)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws/logs?filter=keep"

	conn, _, err := websocketDial(t, wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	type readResult struct {
		msg []byte
		err error
	}
	results := make(chan readResult, 1)
	go func() {
		_, msg, err := conn.ReadMessage()
		results <- readResult{msg: msg, err: err}
	}()

	pumpCtx, stopPump := context.WithCancel(context.Background())
	defer stopPump()
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-pumpCtx.Done():
				return
			case <-ticker.C:
				s.hub.Broadcast([]byte("dropme: ignore"))
				s.hub.Broadcast([]byte("keep: yes"))
			}
		}
	}()

	select {
	case res := <-results:
		if res.err != nil {
			t.Fatalf("read: %v", res.err)
		}
		if !strings.Contains(string(res.msg), "keep") {
			t.Fatalf("expected message to contain 'keep', got %q", string(res.msg))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("did not receive filtered message within deadline")
	}
}

func TestHandleWSLogsBadOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.GET("/ws/logs", s.handleWSLogs)
	ts := httptest.NewServer(r)
	defer ts.Close()

	req, err := http.NewRequest("GET", ts.URL+"/ws/logs", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "http://attacker.com")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Errorf("expected upgrade rejection, got 101")
	}
}

func TestHandleGetAuditHistoryWithLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	hb := audit.NewHistoryBuffer(10)
	for i := 0; i < 5; i++ {
		hb.Write(audit.Event{Action: "apply"})
	}
	s.SetHistory(hb)
	r := gin.New()
	r.GET("/a", s.handleGetAuditHistory)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/a?limit=2", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestRuleSetToDTOAllFields(t *testing.T) {
	rs := docker.FirewallRuleSet{
		Name:      "web",
		Ports:     []uint16{80, 443},
		Protocol:  "",
		Profile:   "edge",
		Log:       true,
		LogPrefix: "P:",
		GeoBlock:  []string{"RU"},
		GeoAllow:  []string{"US"},
		RateLimit: &docker.RateLimitConfig{Rate: 100, Burst: 200},
	}
	dto := RuleSetToDTO(rs)
	if dto.Protocol != "tcp" {
		t.Errorf("expected default tcp, got %q", dto.Protocol)
	}
	if dto.RateLimit == nil || dto.RateLimit.Rate != 100 {
		t.Errorf("rate limit not preserved: %+v", dto.RateLimit)
	}
	if !dto.Log || dto.LogPrefix != "P:" {
		t.Errorf("log fields lost: %+v", dto)
	}
}

func TestRuleSetToDTOExplicitProtocol(t *testing.T) {
	rs := docker.FirewallRuleSet{
		Name:     "udp-rule",
		Protocol: "udp",
	}
	dto := RuleSetToDTO(rs)
	if dto.Protocol != "udp" {
		t.Errorf("expected udp, got %q", dto.Protocol)
	}
	if dto.RateLimit != nil {
		t.Errorf("expected nil rate limit")
	}
}

func TestHandleApplyContainerInvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.POST("/c/:id/apply", s.handleApplyContainer)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/c/not-hex/apply", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleDisableContainerInvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.POST("/c/:id/disable", s.handleDisableContainer)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/c/zzz/disable", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleDisableContainerValid(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.POST("/c/:id/disable", s.handleDisableContainer)
	rec := httptest.NewRecorder()
	id := strings.Repeat("a", 64)
	req := httptest.NewRequest("POST", "/c/"+id+"/disable", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleApplyContainerNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.POST("/c/:id/apply", s.handleApplyContainer)
	rec := httptest.NewRecorder()
	id := strings.Repeat("b", 64)
	req := httptest.NewRequest("POST", "/c/"+id+"/apply", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleGetRulesEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.GET("/r", s.handleGetRules)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/r", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d", rec.Code)
	}
}

type stubBackendWithAppliedIDs struct {
	stubBackend
	ids []string
}

func (s stubBackendWithAppliedIDs) ListAppliedContainerIDs() ([]string, error) { return s.ids, nil }

func TestHandleGetRulesDefaultsEmptyPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	reader := stubDocker{containers: []docker.ContainerInfo{
		{ID: "aaaaaaaaaaaa", Name: "n1", Status: "running"},
	}}
	backend := stubBackendWithAppliedIDs{ids: []string{"aaaaaaaaaaaa"}}
	engine := rules.NewEngine(backend, reader, cfg, logger)
	if err := engine.Rehydrate(context.Background()); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}
	hub := logstream.NewHub(logger)
	traffic := NewTrafficStore()
	s := NewServer(cfg, reader, engine, hub, logger, traffic)

	r := gin.New()
	r.GET("/r", s.handleGetRules)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/r", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var out []RuleEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(out))
	}
	if out[0].DefaultPolicy != "RETURN" {
		t.Errorf("expected defaultPolicy=RETURN for empty policy, got %q", out[0].DefaultPolicy)
	}
}

func TestContainerToDTOEmitsNonNilLabels(t *testing.T) {
	ctr := docker.ContainerInfo{ID: "id1", Name: "n", Status: "running", Labels: nil}
	dto := containerToDTO(ctr, docker.ContainerConfig{}, false)
	if dto.Labels == nil {
		t.Fatal("Labels should be non-nil empty map when ctr.Labels is nil")
	}
	if len(dto.Labels) != 0 {
		t.Errorf("Labels should be empty, got %v", dto.Labels)
	}
}

func TestRuleSetToDTOEmitsNonNilSlices(t *testing.T) {
	dto := RuleSetToDTO(docker.FirewallRuleSet{Name: "rs1"})
	if dto.Ports == nil {
		t.Error("Ports must be non-nil")
	}
	if dto.Allowlist == nil {
		t.Error("Allowlist must be non-nil")
	}
	if dto.Blocklist == nil {
		t.Error("Blocklist must be non-nil")
	}
	body, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(body)
	for _, needle := range []string{`"ports":[]`, `"allowlist":[]`, `"blocklist":[]`} {
		if !strings.Contains(got, needle) {
			t.Errorf("expected %s in JSON, got %s", needle, got)
		}
	}
	for _, needle := range []string{`"ports":null`, `"allowlist":null`, `"blocklist":null`} {
		if strings.Contains(got, needle) {
			t.Errorf("unexpected %s in JSON, got %s", needle, got)
		}
	}
}

func TestHandleGetContainersEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.GET("/c", s.handleGetContainers)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/c", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestHandleGetContainerInvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.GET("/c/:id", s.handleGetContainer)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/c/x", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestHandleGetProfiles(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.GET("/p", s.handleGetProfiles)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/p", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "web") {
		t.Errorf("missing profile entry: %s", rec.Body.String())
	}
}

func TestRespondInternalErrorWithLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.Use(s.requestLogger())
	r.GET("/x", func(c *gin.Context) {
		respondInternalError(c, "code", "msg", errBoom)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestRespondInternalErrorNoLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/x", func(c *gin.Context) {
		respondInternalError(c, "code", "msg", errBoom)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestRespondError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/x", func(c *gin.Context) {
		respondError(c, http.StatusBadRequest, "X", "msg")
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestRespondErrorDetails(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/x", func(c *gin.Context) {
		respondErrorDetails(c, http.StatusBadRequest, "X", "msg", "details")
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	r.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "details") {
		t.Errorf("missing details: %s", rec.Body.String())
	}
}

var errBoom = errFunc("boom")

type errFunc string

func (e errFunc) Error() string { return string(e) }

func TestHandleHealth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Version: "1.2.3"}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.GET("/health", s.handleHealth)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "1.2.3") {
		t.Errorf("missing version: %s", rec.Body.String())
	}
}
