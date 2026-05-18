package api

import (
	"context"
	"errors"
	"log/slog"
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

type errDocker struct{}

func (errDocker) ListContainers(_ context.Context) ([]docker.ContainerInfo, error) {
	return nil, errors.New("docker boom")
}

func (errDocker) Inspect(_ context.Context, _ string) (docker.ContainerInfo, bool, error) {
	return docker.ContainerInfo{}, false, nil
}

func newServerWithDocker(t *testing.T, reader DockerReader) *Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := &config.Config{}
	engine := rules.NewEngine(stubBackend{}, reader, cfg, logger)
	hub := logstream.NewHub(logger)
	return NewServer(cfg, reader, engine, hub, logger, NewTrafficStore())
}

func TestResolveContainer_InvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServerWithDocker(t, stubDocker{})
	r := gin.New()
	r.GET("/c/:id", func(c *gin.Context) {
		_, _ = s.resolveContainer(c, c.Param("id"))
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/c/NOT-HEX", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid id should 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestResolveContainer_DockerError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServerWithDocker(t, errDocker{})
	r := gin.New()
	r.GET("/c/:id", func(c *gin.Context) {
		_, _ = s.resolveContainer(c, c.Param("id"))
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/c/abcdef012345", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable && rec.Code != http.StatusInternalServerError {
		t.Errorf("docker error should fail, got %d", rec.Code)
	}
}

func TestResolveContainer_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newServerWithDocker(t, stubDocker{})
	r := gin.New()
	r.GET("/c/:id", func(c *gin.Context) {
		_, _ = s.resolveContainer(c, c.Param("id"))
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/c/abcdef012345", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestResolveContainer_AmbiguousPrefix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	reader := stubDocker{containers: []docker.ContainerInfo{
		{ID: "abcdef012345aaaa00000000000000000000000000000000000000000000aaaa", Name: "one"},
		{ID: "abcdef012345bbbb00000000000000000000000000000000000000000000bbbb", Name: "two"},
	}}
	s := newServerWithDocker(t, reader)
	r := gin.New()
	r.GET("/c/:id", func(c *gin.Context) {
		_, _ = s.resolveContainer(c, c.Param("id"))
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/c/abcdef012345", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rec.Code)
	}
}

func TestResolveContainer_SinglePrefixMatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	reader := stubDocker{containers: []docker.ContainerInfo{
		{ID: "abcdef012345aaaa00000000000000000000000000000000000000000000aaaa", Name: "one"},
	}}
	s := newServerWithDocker(t, reader)
	r := gin.New()
	r.GET("/c/:id", func(c *gin.Context) {
		ctr, ok := s.resolveContainer(c, c.Param("id"))
		if !ok {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.String(http.StatusOK, ctr.Name)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/c/abcdef012345", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "one" {
		t.Errorf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}
