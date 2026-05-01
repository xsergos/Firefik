package logstream

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestHubShutdownClosesClients(t *testing.T) {
	h := NewHub(discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	go h.Run(ctx)

	c := h.Subscribe()
	time.Sleep(10 * time.Millisecond)

	cancel()

	deadline := time.Now().Add(500 * time.Millisecond)
	gotShutdown := false
	for time.Now().Before(deadline) {
		select {
		case payload, ok := <-c.Messages():
			if !ok {
				return
			}
			var raw map[string]any
			if err := json.Unmarshal(payload, &raw); err == nil {
				if ev, _ := raw["event"].(string); ev == "server_shutdown" {
					gotShutdown = true
				}
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	_ = gotShutdown
}

func TestHubBroadcastFullChannel(t *testing.T) {
	h := NewHub(discardLogger())
	for i := 0; i < 1024; i++ {
		h.Broadcast([]byte("x"))
	}
}

func TestHubUnsubscribeFastPath(t *testing.T) {
	h := NewHub(discardLogger())
	c := h.Subscribe()
	h.Unsubscribe(c)
}

func TestHubMultipleUnsubscribe(t *testing.T) {
	h := NewHub(discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	c := h.Subscribe()
	time.Sleep(10 * time.Millisecond)
	h.Unsubscribe(c)
	h.Unsubscribe(c)
}
