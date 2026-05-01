package api

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto/rand"

	"github.com/gin-gonic/gin"

	"firefik/internal/audit"
	"firefik/internal/autogen"
	"firefik/internal/config"
	"firefik/internal/docker"
	"firefik/internal/logstream"
	"firefik/internal/rules"
)

func makeTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	reader := stubDocker{}
	engine := rules.NewEngine(stubBackend{}, reader, cfg, logger)
	hub := logstream.NewHub(logger)
	traffic := NewTrafficStore()
	return NewServer(cfg, reader, engine, hub, logger, traffic)
}

func TestServerSettersAndGetters(t *testing.T) {
	cfg := &config.Config{ChainName: "F", EffectiveChain: "F", ParentChain: "P"}
	s := makeTestServer(t, cfg)

	s.SetControlPlaneProxy(nil)

	if s.Templates() == nil {
		t.Errorf("templates nil")
	}
	if s.Policies() == nil {
		t.Errorf("policies nil")
	}
	if s.APIToken() == nil {
		t.Errorf("api token nil")
	}
	if s.MetricsToken() == nil {
		t.Errorf("metrics token nil")
	}

	hb := audit.NewHistoryBuffer(5)
	s.SetHistory(hb)
	if s.history != hb {
		t.Errorf("SetHistory failed")
	}

	logger := slog.Default()
	al := audit.New(logger)
	s.SetAuditLogger(al)
	if s.auditLog != al {
		t.Errorf("SetAuditLogger failed")
	}

	obs := autogen.NewObserver()
	s.SetAutogen(obs)
	if s.autogen != obs {
		t.Errorf("SetAutogen failed")
	}
}

func TestValidateSecurityConfigUnix(t *testing.T) {
	cfg := &config.Config{ListenAddr: "unix:///tmp/api.sock"}
	s := makeTestServer(t, cfg)
	if err := s.validateSecurityConfig(); err != nil {
		t.Errorf("unix listener should pass: %v", err)
	}
}

func TestValidateSecurityConfigTCPNoToken(t *testing.T) {
	cfg := &config.Config{ListenAddr: ":8080", APIToken: ""}
	s := makeTestServer(t, cfg)
	if err := s.validateSecurityConfig(); err == nil {
		t.Errorf("expected error for TCP without token")
	}
}

func TestValidateSecurityConfigTCPWithToken(t *testing.T) {
	cfg := &config.Config{ListenAddr: ":8080", APIToken: "tok"}
	s := makeTestServer(t, cfg)
	if err := s.validateSecurityConfig(); err != nil {
		t.Errorf("expected no error: %v", err)
	}
}

func TestBuildTLSConfigEmpty(t *testing.T) {
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	tc, err := s.buildTLSConfig()
	if err != nil || tc != nil {
		t.Errorf("err=%v tc=%v", err, tc)
	}
}

func TestBuildTLSConfigMissingFile(t *testing.T) {
	cfg := &config.Config{ClientCAFile: "/no/such/file"}
	s := makeTestServer(t, cfg)
	if _, err := s.buildTLSConfig(); err == nil {
		t.Errorf("expected error")
	}
}

func TestBuildTLSConfigInvalidPEM(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(tmp, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ClientCAFile: tmp}
	s := makeTestServer(t, cfg)
	if _, err := s.buildTLSConfig(); err == nil {
		t.Errorf("expected error")
	}
}

func TestBuildTLSConfigValid(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	tmp := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(tmp, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ClientCAFile: tmp}
	s := makeTestServer(t, cfg)
	tc, err := s.buildTLSConfig()
	if err != nil || tc == nil {
		t.Errorf("err=%v tc=%v", err, tc)
	}
}

func TestCorsMiddlewareNoAllowed(t *testing.T) {
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	mw := s.corsMiddleware()
	if mw == nil {
		t.Errorf("nil middleware")
	}
	r := gin.New()
	r.Use(mw)
	r.GET("/x", func(c *gin.Context) { c.Status(200) })
	req := httptest.NewRequest("GET", "/x", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestCorsMiddlewareWithAllowedOrigins(t *testing.T) {
	cfg := &config.Config{AllowedOrigins: []string{"https://example.com"}}
	s := makeTestServer(t, cfg)
	mw := s.corsMiddleware()
	if mw == nil {
		t.Errorf("nil middleware")
	}
}

func TestResolveGroupIDNumeric(t *testing.T) {
	gid, err := resolveGroupID("123")
	if err != nil || gid != 123 {
		t.Errorf("err=%v gid=%d", err, gid)
	}
}

func TestResolveGroupIDInvalid(t *testing.T) {
	if _, err := resolveGroupID("not-a-real-group-name-12345"); err == nil {
		t.Errorf("expected error")
	}
}

func TestHandleReadyError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.GET("/ready", s.handleReady)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ready", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequestIDMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestID())
	r.GET("/x", func(c *gin.Context) { c.Status(200) })
	req := httptest.NewRequest("GET", "/x", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Header().Get("X-Request-ID") == "" {
		t.Errorf("expected X-Request-ID header")
	}

	req = httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("X-Request-ID", "custom-id")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Header().Get("X-Request-ID") != "custom-id" {
		t.Errorf("expected custom id")
	}
}

func TestRequestLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.Use(s.requestLogger())
	r.GET("/x", func(c *gin.Context) { c.Status(200) })
	req := httptest.NewRequest("GET", "/x", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestPanicRecovery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.Use(s.panicRecovery())
	r.GET("/p", func(c *gin.Context) { panic("boom") })
	req := httptest.NewRequest("GET", "/p", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != 500 {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestRecordAction(t *testing.T) {
	ts := NewTrafficStore()
	ts.RecordAction("ACCEPT")
	ts.RecordAction("DROP")
	ts.RecordAction("OTHER")
	got := ts.Last(2)
	if len(got) == 0 {
		t.Errorf("expected buckets")
	}
}

func TestTrafficStoreLastClampsTooLarge(t *testing.T) {
	ts := NewTrafficStore()
	ts.RecordAction("ACCEPT")
	got := ts.Last(99999)
	if len(got) > 1440 {
		t.Errorf("too many buckets: %d", len(got))
	}
}

var _ = stubDocker{}
var _ = docker.ContainerInfo{}

func TestBuildWSUpgraderSameOrigin(t *testing.T) {
	logger := slog.Default()
	cfg := &config.Config{}
	up := buildWSUpgrader(cfg, logger)
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "http://example.com")
	if !up.CheckOrigin(req) {
		t.Errorf("expected same-origin to pass")
	}
}

func TestBuildWSUpgraderEmptyOrigin(t *testing.T) {
	logger := slog.Default()
	cfg := &config.Config{}
	up := buildWSUpgrader(cfg, logger)
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	if !up.CheckOrigin(req) {
		t.Errorf("expected empty origin to pass")
	}
}

func TestBuildWSUpgraderAllowedOrigin(t *testing.T) {
	logger := slog.Default()
	cfg := &config.Config{AllowedOrigins: []string{"https://other.com"}}
	up := buildWSUpgrader(cfg, logger)
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "https://other.com")
	if !up.CheckOrigin(req) {
		t.Errorf("expected allowed origin to pass")
	}
}

func TestBuildWSUpgraderRefuse(t *testing.T) {
	logger := slog.Default()
	cfg := &config.Config{}
	up := buildWSUpgrader(cfg, logger)
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "https://attacker.com")
	if up.CheckOrigin(req) {
		t.Errorf("expected cross-origin to be refused")
	}
}

func TestBuildWSUpgraderInvalidOrigin(t *testing.T) {
	logger := slog.Default()
	cfg := &config.Config{}
	up := buildWSUpgrader(cfg, logger)
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "://not-a-url")
	if up.CheckOrigin(req) {
		t.Errorf("expected invalid origin to be refused")
	}
}

func TestConfigureSocketBadPath(t *testing.T) {
	if err := configureSocket("/no/such/path/xyz", 0o600, ""); err == nil {
		t.Errorf("expected error")
	}
}

func TestConfigureSocketBadGroup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sock")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configureSocket(p, 0o600, "definitely-not-a-real-group-XYZ-9999"); err == nil {
		t.Errorf("expected error for unknown group")
	}
}

func TestRunInvalidSecurityConfig(t *testing.T) {
	cfg := &config.Config{ListenAddr: ":0", APIToken: ""}
	s := makeTestServer(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Run(ctx); err == nil {
		t.Errorf("expected security validation error")
	}
}

func TestRunBuildTLSError(t *testing.T) {
	cfg := &config.Config{
		ListenAddr:   ":0",
		APIToken:     "tok",
		ClientCAFile: "/no/such/file",
	}
	s := makeTestServer(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Run(ctx); err == nil {
		t.Errorf("expected tls error")
	}
}

func TestRegisterRoutesSmoke(t *testing.T) {
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	s.registerRoutes(r)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("/health code=%d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/v1/openapi.json", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("/openapi.json code=%d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/v1/openapi.yaml", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("/openapi.yaml code=%d", rec.Code)
	}
}
