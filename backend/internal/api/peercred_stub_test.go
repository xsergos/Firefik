//go:build !linux

package api

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestPeerCredAllow_PassesThrough(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(peerCredAllow([]int{0}, "anyone"))
	r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body=%q", rec.Body.String())
	}
}

func TestPeerUIDFromConn_AlwaysMinusOne(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if got := peerUIDFromConn(server); got != -1 {
		t.Errorf("got %d, want -1", got)
	}
}
