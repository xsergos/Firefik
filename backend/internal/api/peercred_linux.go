//go:build linux

package api

import (
	"net"
	"net/http"
	"strings"
	"syscall"

	"github.com/gin-gonic/gin"
)

func peerCredAllow(allowed []int, listenAddr string) gin.HandlerFunc {
	if len(allowed) == 0 || !strings.HasPrefix(listenAddr, "unix://") {
		return func(c *gin.Context) { c.Next() }
	}
	set := make(map[int]struct{}, len(allowed))
	for _, uid := range allowed {
		set[uid] = struct{}{}
	}
	return func(c *gin.Context) {
		raw, ok := c.Request.Context().Value(peerCredContextKey{}).(int)
		if !ok {
			c.Next()
			return
		}
		if _, ok := set[raw]; !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "peer uid not allowed"})
			return
		}
		c.Next()
	}
}

func peerUIDFromConn(conn net.Conn) int {
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
		if ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); err == nil {
			uid = int(ucred.Uid)
		}
	})
	return uid
}
