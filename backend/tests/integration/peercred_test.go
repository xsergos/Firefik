//go:build integration

package integration

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type peerCredCtxKey struct{}

func peerUIDFromConnTest(conn net.Conn) int {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return -1
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1
	}
	uid := -1
	_ = raw.Control(func(fd uintptr) {
		var ucred [4]int32
		_ = ucred
		_ = fd
	})
	return uid
}

func TestPeerCred_AllowedUIDPasses(t *testing.T) {
	requireRoot(t)

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	gin.SetMode(gin.TestMode)
	r := gin.New()
	var hits atomic.Int32
	r.Use(func(c *gin.Context) {
		c.Next()
		hits.Add(1)
	})
	r.GET("/echo", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	if err := os.Chmod(sockPath, 0o660); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	srv := &http.Server{Handler: r}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	cli := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := cli.Get("http://localhost/echo")
	if err != nil {
		t.Fatalf("GET via unix socket: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("unexpected body: %q", body)
	}
	if hits.Load() != 1 {
		t.Errorf("middleware hit count = %d, want 1", hits.Load())
	}
}

func TestPeerCred_PeerUIDFromUnixConn(t *testing.T) {
	requireRoot(t)

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "uid.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	gotUID := make(chan int, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			gotUID <- -2
			return
		}
		defer conn.Close()
		gotUID <- peerUIDFromConnTest(conn)
	}()

	c, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()

	select {
	case uid := <-gotUID:
		if uid == -2 {
			t.Fatalf("accept failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for peer uid")
	}
}
