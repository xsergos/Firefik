//go:build !linux

package api

import (
	"net"

	"github.com/gin-gonic/gin"
)

func peerCredAllow(_ []int, _ string) gin.HandlerFunc {
	return func(c *gin.Context) { c.Next() }
}

func peerUIDFromConn(_ net.Conn) int { return -1 }
