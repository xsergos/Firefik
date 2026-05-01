package controlplane

import (
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

var logUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin:     func(_ *http.Request) bool { return true },
}

const (
	logWriteWait     = 5 * time.Second
	logPingInterval  = 30 * time.Second
	logReadDeadline  = 60 * time.Second
	logShutdownGrace = 200 * time.Millisecond
)

func (s *HTTPServer) streamLogs(w http.ResponseWriter, r *http.Request, agentID string) {
	if s.Registry == nil || s.Registry.LogHub() == nil {
		http.Error(w, "log hub unavailable", http.StatusServiceUnavailable)
		return
	}
	conn, err := logUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	sub := s.Registry.LogHub().Subscribe(agentID)
	defer sub.Close()

	_ = conn.SetReadDeadline(time.Now().Add(logReadDeadline))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(logReadDeadline))
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

	ping := time.NewTicker(logPingInterval)
	defer ping.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-readDone:
			return
		case line, ok := <-sub.C():
			if !ok {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(logWriteWait))
			if err := conn.WriteJSON(line); err != nil {
				return
			}
		case <-ping.C:
			_ = conn.SetWriteDeadline(time.Now().Add(logWriteWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
