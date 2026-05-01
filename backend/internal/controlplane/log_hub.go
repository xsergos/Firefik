package controlplane

import (
	"sync"
	"sync/atomic"
)

const logSubBuffer = 256

type LogSubscription struct {
	id      uint64
	agentID string
	hub     *LogHub
	ch      chan LogLine
}

func (s *LogSubscription) C() <-chan LogLine { return s.ch }

func (s *LogSubscription) Close() {
	if s == nil || s.hub == nil {
		return
	}
	s.hub.unsubscribe(s)
}

type LogHub struct {
	mu     sync.Mutex
	nextID uint64
	byID   map[string]map[uint64]*LogSubscription
	allCh  map[uint64]*LogSubscription

	dropped atomic.Uint64
}

func NewLogHub() *LogHub {
	return &LogHub{
		byID:  map[string]map[uint64]*LogSubscription{},
		allCh: map[uint64]*LogSubscription{},
	}
}

func (h *LogHub) Subscribe(agentID string) *LogSubscription {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextID++
	sub := &LogSubscription{
		id:      h.nextID,
		agentID: agentID,
		hub:     h,
		ch:      make(chan LogLine, logSubBuffer),
	}
	if agentID == "" {
		h.allCh[sub.id] = sub
	} else {
		set, ok := h.byID[agentID]
		if !ok {
			set = map[uint64]*LogSubscription{}
			h.byID[agentID] = set
		}
		set[sub.id] = sub
	}
	return sub
}

func (h *LogHub) unsubscribe(sub *LogSubscription) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if sub.agentID == "" {
		delete(h.allCh, sub.id)
	} else if set, ok := h.byID[sub.agentID]; ok {
		delete(set, sub.id)
		if len(set) == 0 {
			delete(h.byID, sub.agentID)
		}
	}
	close(sub.ch)
}

func (h *LogHub) Publish(line LogLine) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.allCh {
		select {
		case s.ch <- line:
		default:
			h.dropped.Add(1)
		}
	}
	if set, ok := h.byID[line.Agent.InstanceID]; ok {
		for _, s := range set {
			select {
			case s.ch <- line:
			default:
				h.dropped.Add(1)
			}
		}
	}
}

func (h *LogHub) Dropped() uint64 { return h.dropped.Load() }
