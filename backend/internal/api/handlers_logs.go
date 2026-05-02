package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// @Summary Subscribe to the live event stream
// @Description WebSocket endpoint. Frames are JSON `{event,…}` objects (see backend/internal/logstream) and periodic `{event:"dropped",count:N}` control messages when a slow consumer lags the hub.
// @Tags logs
// @Security BearerAuth
// @Param filter query string false "substring filter applied to each frame before send"
// @Success 101 {string} string "switching protocols"
// @Router /ws/logs [get]
func (s *Server) handleWSLogs(c *gin.Context) {
	filter := strings.TrimSpace(c.Query("filter"))

	key := c.ClientIP()
	if !s.wsCounter.admit(key) {
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"error": "too many WebSocket subscribers from this client",
		})
		return
	}
	defer s.wsCounter.release(key)

	conn, err := s.wsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		s.logger.Warn("ws upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	client := s.hub.Subscribe()
	defer s.hub.Unsubscribe(client)

	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	})

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	ctx := c.Request.Context()

	for {
		select {
		case <-ctx.Done():
			return

		case <-readDone:
			return

		case <-pingTicker.C:
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}

		case msg, ok := <-client.Messages():
			if !ok {
				return
			}
			if filter != "" && !strings.Contains(string(msg), filter) {
				continue
			}
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				s.logger.Debug("ws write failed", "error", err)
				return
			}
		}
	}
}

// @Summary Liveness / health probe
// @Description Always returns 200 while firefik is serving. Reports the build version.
// @Tags health
// @Produce json
// @Success 200 {object} StatusResponse
// @Router /health [get]
func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, StatusResponse{Status: "ok", Version: s.cfg.Version})
}

// @Summary List rule profiles
// @Description Returns the set of built-in rule-set profiles that labels can reference (`firefik.rules.<name>.profile=<profile>`).
// @Tags rules
// @Produce json
// @Security BearerAuth
// @Success 200 {array} ProfileEntry
// @Router /api/rules/profiles [get]
func (s *Server) handleGetProfiles(c *gin.Context) {
	c.JSON(http.StatusOK, []ProfileEntry{
		{Name: "web", Description: "Allow HTTP/HTTPS from everywhere"},
		{Name: "internal", Description: "Allow traffic from RFC1918 only"},
		{Name: "custom", Description: "No preset rules"},
	})
}

// @Summary Audit history snapshot
// @Description Returns the most recent audit events kept in the in-memory ring buffer. Populated only when `history` is included in `FIREFIK_AUDIT_SINK`. Supports `?limit=<n>` and `?since=<RFC3339>`.
// @Tags logs
// @Produce json
// @Security BearerAuth
// @Param limit query int false "maximum events to return (0 = all)"
// @Param since query string false "RFC3339 timestamp; only events strictly after this are returned"
// @Success 200 {array} object
// @Failure 400 {object} APIError
// @Router /api/audit/history [get]
func (s *Server) handleGetAuditHistory(c *gin.Context) {
	if s.history == nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	events := s.history.Snapshot()
	if q := c.Query("since"); q != "" {
		t, err := time.Parse(time.RFC3339, q)
		if err != nil {
			respondErrorDetails(c, http.StatusBadRequest, ErrCodeInvalidBody,
				"invalid 'since' query parameter", "expected RFC3339 timestamp")
			return
		}
		filtered := events[:0]
		for _, ev := range events {
			if ev.Timestamp.After(t) {
				filtered = append(filtered, ev)
			}
		}
		events = filtered
	}
	if q := c.Query("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n < len(events) {
			events = events[len(events)-n:]
		}
	}
	c.JSON(http.StatusOK, events)
}

// @Summary List rule templates
// @Description Returns rule templates loaded from `FIREFIK_TEMPLATES_FILE`. Each template has a deterministic 16-hex version derived from its canonical content.
// @Tags rules
// @Produce json
// @Security BearerAuth
// @Success 200 {array} object
// @Router /api/rules/templates [get]
func (s *Server) handleGetTemplates(c *gin.Context) {
	list := s.templates.List()
	c.JSON(http.StatusOK, list)
}
