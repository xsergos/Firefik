package logstream

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHub_SubscribeBroadcast(t *testing.T) {
	h := NewHub(discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	c := h.Subscribe()
	defer h.Unsubscribe(c)

	time.Sleep(10 * time.Millisecond)

	h.Broadcast([]byte(`{"ts":"now","action":"DROP"}`))

	select {
	case got := <-c.Messages():
		if string(got) != `{"ts":"now","action":"DROP"}` {
			t.Fatalf("unexpected payload: %s", got)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("subscriber did not receive broadcast")
	}
}

func TestHub_SlowClient_EmitsDropControl(t *testing.T) {
	h := NewHub(discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	c := h.Subscribe()
	defer h.Unsubscribe(c)
	time.Sleep(10 * time.Millisecond)

	for i := 0; i < 200; i++ {
		h.Broadcast([]byte(`{"ts":"t","action":"DROP"}`))
	}
	time.Sleep(50 * time.Millisecond)

	sawControl := false
	for i := 0; i < 100; i++ {
		select {
		case payload := <-c.Messages():
			var raw map[string]any
			if err := json.Unmarshal(payload, &raw); err != nil {
				continue
			}
			if ev, ok := raw["event"].(string); ok && ev == "dropped" {
				sawControl = true
			}
		case <-time.After(50 * time.Millisecond):
			i = 100
		}
	}
	h.Broadcast([]byte(`{"ts":"final","action":"ACCEPT"}`))
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) && !sawControl {
		select {
		case payload := <-c.Messages():
			var raw map[string]any
			if err := json.Unmarshal(payload, &raw); err != nil {
				continue
			}
			if ev, ok := raw["event"].(string); ok && ev == "dropped" {
				sawControl = true
			}
		case <-time.After(50 * time.Millisecond):
		}
	}

	if !sawControl {
		t.Fatalf("slow client should have received a `dropped` control message")
	}
}
