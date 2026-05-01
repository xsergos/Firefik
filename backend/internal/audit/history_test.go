package audit

import (
	"testing"
	"time"
)

func TestHistoryBuffer_UnderCapacity(t *testing.T) {
	h := NewHistoryBuffer(5)
	for i := 0; i < 3; i++ {
		_ = h.Write(Event{Action: "apply", Timestamp: time.Unix(int64(i), 0)})
	}
	snap := h.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("want 3 events, got %d", len(snap))
	}
	if snap[0].Timestamp.Unix() != 0 || snap[2].Timestamp.Unix() != 2 {
		t.Errorf("wrong ordering: %+v", snap)
	}
}

func TestHistoryBuffer_Wraparound(t *testing.T) {
	h := NewHistoryBuffer(3)
	for i := 0; i < 7; i++ {
		_ = h.Write(Event{Action: "apply", Timestamp: time.Unix(int64(i), 0)})
	}
	snap := h.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("want 3 events, got %d", len(snap))
	}
	if snap[0].Timestamp.Unix() != 4 || snap[2].Timestamp.Unix() != 6 {
		t.Errorf("ring should hold the last 3: %+v", snap)
	}
}

func TestHistoryBuffer_Empty(t *testing.T) {
	h := NewHistoryBuffer(10)
	snap := h.Snapshot()
	if len(snap) != 0 {
		t.Errorf("empty buffer should snapshot as nil-or-zero, got %d", len(snap))
	}
}
