// @title Firefik API
// @version 0.3
// @description Container-scoped firewall control plane. Authentication is bearer-token on TCP listeners and peer-credentials on unix sockets.
// @license.name Apache-2.0
// @basePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	"firefik/internal/api/openapi"
	"firefik/internal/audit"
	"firefik/internal/autogen"
	"firefik/internal/config"
	"firefik/internal/docker"
	"firefik/internal/logstream"
	"firefik/internal/rules"
)

type DockerReader interface {
	ListContainers(ctx context.Context) ([]docker.ContainerInfo, error)
	Inspect(ctx context.Context, id string) (docker.ContainerInfo, bool, error)
}

type Server struct {
	cfg          *config.Config
	docker       DockerReader
	engine       *rules.Engine
	hub          *logstream.Hub
	logger       *slog.Logger
	traffic      *TrafficStore
	wsUpgrader   websocket.Upgrader
	apiToken     *TokenProvider
	metricsToken *TokenProvider
	wsCounter    *wsCounter
	templates    *TemplateStore
	history      *audit.HistoryBuffer
	policies     *PolicyStore
	autogen      *autogen.Observer
	auditLog     *audit.Logger
	cpProxy      *ControlPlaneProxy
}

func (s *Server) SetControlPlaneProxy(p *ControlPlaneProxy) { s.cpProxy = p }

func (s *Server) SetAuditLogger(l *audit.Logger) { s.auditLog = l }

func (s *Server) SetAutogen(o *autogen.Observer) { s.autogen = o }

func (s *Server) Templates() *TemplateStore { return s.templates }
func (s *Server) Policies() *PolicyStore    { return s.policies }
func (s *Server) SetHistory(h *audit.HistoryBuffer) {
	s.history = h
}

func (s *Server) APIToken() *TokenProvider     { return s.apiToken }
func (s *Server) MetricsToken() *TokenProvider { return s.metricsToken }

func NewServer(
	cfg *config.Config,
	dockerClient DockerReader,
	engine *rules.Engine,
	hub *logstream.Hub,
	logger *slog.Logger,
	traffic *TrafficStore,
) *Server {
	metricsToken := cfg.MetricsToken
	if metricsToken == "" {
		metricsToken = cfg.APIToken
	}
	return &Server{
		cfg:          cfg,
		docker:       dockerClient,
		engine:       engine,
		hub:          hub,
		logger:       logger,
		traffic:      traffic,
		wsUpgrader:   buildWSUpgrader(cfg, logger),
		apiToken:     NewTokenProvider(cfg.APIToken),
		metricsToken: NewTokenProvider(metricsToken),
		wsCounter:    newWSCounter(cfg.WSMaxSubscribers),
		templates:    NewTemplateStore(nil),
		policies:     NewPolicyStore(),
	}
}

func buildWSUpgrader(cfg *config.Config, logger *slog.Logger) websocket.Upgrader {
	allowed := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		allowed[strings.ToLower(o)] = struct{}{}
	}
	return websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 4096,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			u, err := url.Parse(origin)
			if err != nil {
				logger.Warn("ws: invalid Origin", "origin", origin)
				return false
			}
			if strings.EqualFold(u.Host, r.Host) {
				return true
			}
			if _, ok := allowed[strings.ToLower(origin)]; ok {
				return true
			}
			logger.Warn("ws: cross-origin upgrade refused", "origin", origin, "host", r.Host)
			return false
		},
	}
}

func (s *Server) Run(ctx context.Context) error {
	gin.SetMode(gin.ReleaseMode)

	if err := s.validateSecurityConfig(); err != nil {
		return err
	}

	r := gin.New()
	r.Use(s.panicRecovery())
	r.Use(otelgin.Middleware("firefik-api"))
	r.Use(requestID())
	r.Use(s.requestLogger())
	r.Use(s.corsMiddleware())
	r.Use(bodySizeLimit(s.cfg.MaxBodyBytes))
	r.Use(peerCredAllow(s.cfg.AllowedUIDs, s.cfg.ListenAddr))

	s.registerRoutes(r)

	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      tlsConfig,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if uid := peerUIDFromConn(c); uid >= 0 {
				ctx = context.WithValue(ctx, peerCredContextKey{}, uid)
			}
			return ctx
		},
	}

	var ln net.Listener
	addr := s.cfg.ListenAddr

	if strings.HasPrefix(addr, "unix://") {
		sockPath := strings.TrimPrefix(addr, "unix://")
		_ = os.Remove(sockPath)
		var err error
		ln, err = net.Listen("unix", sockPath)
		if err != nil {
			return fmt.Errorf("listen unix %s: %w", sockPath, err)
		}
		if err := configureSocket(sockPath, s.cfg.SocketMode, s.cfg.SocketGroup); err != nil {
			_ = ln.Close()
			_ = os.Remove(sockPath)
			return err
		}
		defer os.Remove(sockPath)
		s.logger.Info("listening on unix socket", "path", sockPath, "mode", s.cfg.SocketMode.String(), "group", s.cfg.SocketGroup)
	} else {
		srv.Addr = addr
		s.logger.Info("listening on tcp", "addr", addr, "auth_required", s.cfg.APIToken != "")
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("graceful shutdown failed", "error", err)
		}
	}()

	if ln != nil {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("serve unix %s: %w", strings.TrimPrefix(addr, "unix://"), err)
		}
	} else {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
	}
	return nil
}

func (s *Server) validateSecurityConfig() error {
	if strings.HasPrefix(s.cfg.ListenAddr, "unix://") {
		return nil
	}
	if s.cfg.APIToken == "" {
		return fmt.Errorf("refusing to start: TCP listener %q requires FIREFIK_API_TOKEN (or FIREFIK_API_TOKEN_FILE) to be set", s.cfg.ListenAddr)
	}
	return nil
}

func (s *Server) buildTLSConfig() (*tls.Config, error) {
	if s.cfg.ClientCAFile == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(s.cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", s.cfg.ClientCAFile)
	}
	return &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}, nil
}

func (s *Server) corsMiddleware() gin.HandlerFunc {
	if len(s.cfg.AllowedOrigins) == 0 {
		return func(c *gin.Context) { c.Next() }
	}
	return cors.New(cors.Config{
		AllowOrigins:     s.cfg.AllowedOrigins,
		AllowMethods:     []string{"GET", "HEAD", "OPTIONS", "POST"},
		AllowHeaders:     []string{"Authorization", "Content-Type", "X-Request-ID"},
		ExposeHeaders:    []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           time.Hour,
	})
}

func (s *Server) registerRoutes(r *gin.Engine) {
	r.GET("/health", s.handleHealth)
	r.GET("/live", s.handleHealth)
	r.GET("/ready", s.handleReady)

	r.GET("/api/v1/openapi.json", s.handleOpenAPIJSON)
	r.GET("/api/v1/openapi.yaml", s.handleOpenAPIYAML)

	authedAPI := r.Group("/api", authBearerDynamic(s.apiToken), csrfOriginGuard(s.cfg.AllowedOrigins))
	if s.cfg.RateLimitRPS > 0 && s.cfg.RateLimitBurst > 0 {
		authedAPI.Use(newRateLimiter(s.cfg.RateLimitRPS, s.cfg.RateLimitBurst).middleware())
	}
	authedAPI.GET("/containers", s.handleGetContainers)
	authedAPI.GET("/containers/:id", s.handleGetContainer)
	authedAPI.POST("/containers/:id/apply", s.handleApplyContainer)
	authedAPI.POST("/containers/:id/disable", s.handleDisableContainer)
	authedAPI.POST("/containers/bulk", s.handleBulkContainers)
	authedAPI.GET("/rules", s.handleGetRules)
	authedAPI.GET("/rules/profiles", s.handleGetProfiles)
	authedAPI.GET("/rules/templates", s.handleGetTemplates)
	authedAPI.GET("/stats", s.handleGetStats)
	authedAPI.GET("/audit/history", s.handleGetAuditHistory)
	authedAPI.GET("/policies", s.handleGetPolicies)
	authedAPI.GET("/policies/:name", s.handleGetPolicy)
	authedAPI.POST("/policies/validate", s.handleValidatePolicy)
	authedAPI.PUT("/policies/:name", s.handleWritePolicy)
	authedAPI.POST("/policies/:name/simulate", s.handleSimulatePolicy)
	authedAPI.GET("/autogen/proposals", s.handleGetAutogenProposals)
	authedAPI.POST("/autogen/proposals/:id/approve", s.handleApproveAutogen)
	authedAPI.POST("/autogen/proposals/:id/reject", s.handleRejectAutogen)

	if s.cpProxy != nil {
		authedAPI.GET("/templates", s.cpProxy.handleTemplatesList)
		authedAPI.POST("/templates", s.cpProxy.handleTemplatePublish)
		authedAPI.GET("/templates/:name", s.cpProxy.handleTemplateGet)
		authedAPI.GET("/approvals", s.cpProxy.handleApprovalsList)
		authedAPI.POST("/approvals", s.cpProxy.handleApprovalCreate)
		authedAPI.GET("/approvals/:id", s.cpProxy.handleApprovalGet)
		authedAPI.POST("/approvals/:id/approve", s.cpProxy.handleApprovalApprove)
		authedAPI.POST("/approvals/:id/reject", s.cpProxy.handleApprovalReject)
	}

	ws := r.Group("/ws", authBearerDynamic(s.apiToken))
	ws.GET("/logs", s.handleWSLogs)

	metricsHandlers := []gin.HandlerFunc{authBearerDynamic(s.metricsToken)}
	if s.cfg.MetricsRateRPS > 0 && s.cfg.MetricsRateBurst > 0 {
		metricsHandlers = append(metricsHandlers,
			newRateLimiter(s.cfg.MetricsRateRPS, s.cfg.MetricsRateBurst).middlewareAllMethods(),
		)
	}
	metricsHandlers = append(metricsHandlers, gin.WrapH(promhttp.Handler()))
	r.GET("/metrics", metricsHandlers...)
}

// @Summary OpenAPI specification (JSON)
// @Description Returns the embedded `swagger.json` generated by swaggo. Unauthenticated.
// @Tags meta
// @Produce json
// @Success 200 {string} string "swagger 2.0 JSON document"
// @Router /api/v1/openapi.json [get]
func (s *Server) handleOpenAPIJSON(c *gin.Context) {
	c.Data(http.StatusOK, "application/json; charset=utf-8", openapi.SwaggerJSON)
}

// @Summary OpenAPI specification (YAML)
// @Description Returns the embedded `swagger.yaml` generated by swaggo. Unauthenticated.
// @Tags meta
// @Produce plain
// @Success 200 {string} string "swagger 2.0 YAML document"
// @Router /api/v1/openapi.yaml [get]
func (s *Server) handleOpenAPIYAML(c *gin.Context) {
	c.Data(http.StatusOK, "application/yaml; charset=utf-8", openapi.SwaggerYAML)
}

// @Summary Readiness probe
// @Description Returns 200 when firefik can talk to Docker, 503 otherwise.
// @Tags health
// @Produce json
// @Success 200 {object} StatusResponse
// @Failure 503 {object} StatusResponse
// @Router /ready [get]
func (s *Server) handleReady(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	if _, err := s.docker.ListContainers(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, StatusResponse{Status: "not ready", Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, StatusResponse{Status: "ready"})
}

func configureSocket(path string, mode os.FileMode, group string) error {
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod unix socket: %w", err)
	}
	if group == "" {
		return nil
	}
	gid, err := resolveGroupID(group)
	if err != nil {
		return fmt.Errorf("resolve socket group %q: %w", group, err)
	}
	if err := os.Chown(path, -1, gid); err != nil {
		return fmt.Errorf("chown unix socket to gid %d: %w", gid, err)
	}
	return nil
}

func resolveGroupID(group string) (int, error) {
	if gid, err := strconv.Atoi(group); err == nil {
		return gid, nil
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return 0, err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("parse gid %q: %w", g.Gid, err)
	}
	return gid, nil
}

func (s *Server) panicRecovery() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, err any) {
		s.logger.Error("panic recovered", "error", err, "path", c.Request.URL.Path, "request_id", c.GetHeader("X-Request-ID"))
		c.AbortWithStatus(http.StatusInternalServerError)
	})
}

func requestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if id == "" {
			id = uuid.New().String()
		}
		c.Request.Header.Set("X-Request-ID", id)
		c.Header("X-Request-ID", id)
		c.Next()
	}
}

func (s *Server) requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		reqID := c.GetHeader("X-Request-ID")
		c.Set("request_id", reqID)
		c.Set("logger", s.logger.With("request_id", reqID))
		c.Next()
		if c.Writer.Status() == http.StatusSwitchingProtocols {
			return
		}
		s.logger.Info("request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"latency_ms", time.Since(start).Milliseconds(),
			"client_ip", c.ClientIP(),
			"request_id", reqID,
		)
	}
}
