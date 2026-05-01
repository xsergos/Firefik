package logstream

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var droppedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "firefik_logstream_dropped_total",
	Help: "Total log messages silently dropped due to full broadcast or client send channels.",
})

type Client struct {
	send      chan []byte
	dropCount atomic.Uint64
}

type Hub struct {
	mu         sync.RWMutex
	clients    map[*Client]struct{}
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	logger     *slog.Logger
}

type controlMessage struct {
	Event string `json:"event"`
	Count uint64 `json:"count,omitempty"`
}

func NewHub(logger *slog.Logger) *Hub {
	return &Hub{
		clients:    make(map[*Client]struct{}),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client, 16),
		unregister: make(chan *Client, 16),
		logger:     logger,
	}
}

func (h *Hub) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			h.sendShutdown()
			return

		case c := <-h.register:
			h.mu.Lock()
			h.clients[c] = struct{}{}
			h.mu.Unlock()

		case c := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[c]; ok {
				delete(h.clients, c)
				close(c.send)
			}
			h.mu.Unlock()

		case msg := <-h.broadcast:
			h.mu.RLock()
			for c := range h.clients {
				if n := c.dropCount.Swap(0); n > 0 {
					if payload, err := marshalControl("dropped", n); err == nil {
						select {
						case c.send <- payload:
						default:
							c.dropCount.Add(n)
						}
					}
				}
				select {
				case c.send <- msg:
				default:
					droppedTotal.Inc()
					c.dropCount.Add(1)
					h.logger.Debug("dropped log message: slow client")
				}
			}
			h.mu.RUnlock()
		}
	}
}

func (h *Hub) sendShutdown() {
	payload, err := marshalControl("server_shutdown", 0)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case c.send <- payload:
		default:
		}
		close(c.send)
		delete(h.clients, c)
	}
}

func marshalControl(event string, count uint64) ([]byte, error) {
	return json.Marshal(controlMessage{Event: event, Count: count})
}

func (h *Hub) Broadcast(msg []byte) {
	select {
	case h.broadcast <- msg:
	default:
		droppedTotal.Inc()
		h.logger.Warn("dropped log message: broadcast channel full")
	}
}

func (h *Hub) Subscribe() *Client {
	c := &Client{send: make(chan []byte, 64)}
	select {
	case h.register <- c:
	default:
		h.mu.Lock()
		h.clients[c] = struct{}{}
		h.mu.Unlock()
	}
	return c
}

func (h *Hub) Unsubscribe(c *Client) {
	select {
	case h.unregister <- c:
	default:
		h.mu.Lock()
		if _, ok := h.clients[c]; ok {
			delete(h.clients, c)
			close(c.send)
		}
		h.mu.Unlock()
	}
}

func (c *Client) Messages() <-chan []byte {
	return c.send
}
