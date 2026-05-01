package controlplane

import (
	"log/slog"
	"sync"
	"time"

	"firefik/internal/audit"
)

type SinkFanOut struct {
	mu     sync.RWMutex
	Sinks  []audit.Sink
	Logger *slog.Logger
}

func (f *SinkFanOut) Emit(action string, metadata map[string]string) {
	if f == nil {
		return
	}
	f.mu.RLock()
	sinks := make([]audit.Sink, len(f.Sinks))
	copy(sinks, f.Sinks)
	f.mu.RUnlock()
	if len(sinks) == 0 {
		return
	}
	ev := audit.Event{
		Timestamp: time.Now().UTC(),
		Action:    action,
		Source:    audit.SourceControlPlane,
		Metadata:  metadata,
	}
	for _, sink := range sinks {
		if err := sink.Write(ev); err != nil && f.Logger != nil {
			f.Logger.Warn("audit fan-out write failed", "action", action, "error", err)
		}
	}
}
