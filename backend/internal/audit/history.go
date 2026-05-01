package audit

import "sync"

type HistoryBuffer struct {
	mu     sync.Mutex
	cap    int
	ring   []Event
	head   int
	filled bool
}

func NewHistoryBuffer(size int) *HistoryBuffer {
	if size <= 0 {
		size = 500
	}
	return &HistoryBuffer{cap: size, ring: make([]Event, size)}
}

func (h *HistoryBuffer) Write(ev Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ring[h.head] = ev
	h.head = (h.head + 1) % h.cap
	if h.head == 0 {
		h.filled = true
	}
	return nil
}

func (h *HistoryBuffer) Close() error { return nil }

func (h *HistoryBuffer) Snapshot() []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	size := h.head
	if h.filled {
		size = h.cap
	}
	out := make([]Event, 0, size)
	if !h.filled {
		out = append(out, h.ring[:h.head]...)
		return out
	}
	out = append(out, h.ring[h.head:]...)
	out = append(out, h.ring[:h.head]...)
	return out
}
