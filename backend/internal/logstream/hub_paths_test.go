package logstream

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestHubSubscribeFallbackWhenRegisterFull(t *testing.T) {
	h := NewHub(discardLogger())
	clients := make([]*Client, 0, 100)
	for i := 0; i < 100; i++ {
		clients = append(clients, h.Subscribe())
	}
	if len(h.clients)+len(h.register) < 100 {
		t.Errorf("expected clients to be tracked: clients=%d register=%d", len(h.clients), len(h.register))
	}
}

func TestHubUnsubscribeFallbackWhenUnregisterFull(t *testing.T) {
	h := NewHub(discardLogger())
	clients := make([]*Client, 0, 50)
	for i := 0; i < 50; i++ {
		c := h.Subscribe()
		clients = append(clients, c)
	}
	for _, c := range clients {
		h.Unsubscribe(c)
	}
}

func TestHubUnsubscribeUnknownClientNoop(t *testing.T) {
	h := NewHub(discardLogger())
	c := &Client{send: make(chan []byte, 1)}
	h.Unsubscribe(c)
}

func TestHubConcurrentSubscribeBroadcastUnsubscribe(t *testing.T) {
	h := NewHub(discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				c := h.Subscribe()
				select {
				case <-c.Messages():
				default:
				}
				h.Unsubscribe(c)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			h.Broadcast([]byte("x"))
			time.Sleep(time.Millisecond)
		}
	}()
	wg.Wait()
}

func TestHubSendShutdownEmpty(t *testing.T) {
	h := NewHub(discardLogger())
	h.sendShutdown()
}

func TestHubSendShutdownDeliversAndClosesClients(t *testing.T) {
	h := NewHub(discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	go h.Run(ctx)

	c := h.Subscribe()
	time.Sleep(20 * time.Millisecond)

	cancel()

	deadline := time.Now().Add(500 * time.Millisecond)
	closed := false
	for time.Now().Before(deadline) {
		select {
		case _, ok := <-c.Messages():
			if !ok {
				closed = true
			}
		case <-time.After(20 * time.Millisecond):
		}
		if closed {
			break
		}
	}
	if !closed {
		t.Errorf("expected client channel to be closed after shutdown")
	}
}

func TestHubMarshalControl(t *testing.T) {
	b, err := marshalControl("dropped", 5)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(b) == 0 {
		t.Errorf("empty payload")
	}
}
