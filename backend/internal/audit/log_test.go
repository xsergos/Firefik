package audit

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
)

type logCaptureSink struct {
	mu     sync.Mutex
	events []Event
	err    error
	closed bool
}

func (c *logCaptureSink) Write(ev Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return c.err
}

func (c *logCaptureSink) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func newTestLogger() *Logger {
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestNew(t *testing.T) {
	l := newTestLogger()
	if l == nil {
		t.Fatal("nil logger")
	}
	if l.sink != nil {
		t.Errorf("expected nil sink")
	}
}

func TestWithSink(t *testing.T) {
	l := newTestLogger()
	cs := &logCaptureSink{}
	l2 := l.WithSink(cs)
	if l2.sink == nil {
		t.Errorf("expected sink set")
	}
	if l.sink != nil {
		t.Errorf("original should not be modified")
	}
}

func TestCloseNoSink(t *testing.T) {
	if err := newTestLogger().Close(); err != nil {
		t.Errorf("err: %v", err)
	}
}

func TestCloseWithSink(t *testing.T) {
	cs := &logCaptureSink{}
	l := newTestLogger().WithSink(cs)
	if err := l.Close(); err != nil {
		t.Errorf("err: %v", err)
	}
	if !cs.closed {
		t.Errorf("sink not closed")
	}
}

func TestEmitNoSink(t *testing.T) {
	l := newTestLogger()
	l.emit(Event{Action: "x"})
}

func TestEmitWithSink(t *testing.T) {
	cs := &logCaptureSink{}
	l := newTestLogger().WithSink(cs)
	l.emit(Event{Action: "test"})
	if len(cs.events) != 1 {
		t.Errorf("events = %d", len(cs.events))
	}
}

func TestEmitSinkError(t *testing.T) {
	cs := &logCaptureSink{err: errors.New("oops")}
	l := newTestLogger().WithSink(cs)
	l.emit(Event{Action: "test"})
}

func TestShortID(t *testing.T) {
	cases := map[string]string{
		"":             "",
		"abc":          "abc",
		"abcdefghijkl": "abcdefghijkl",
		"abcdefghijklmnop": "abcdefghijkl",
	}
	for in, want := range cases {
		if got := shortID(in); got != want {
			t.Errorf("shortID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRulesApplied(t *testing.T) {
	cs := &logCaptureSink{}
	l := newTestLogger().WithSink(cs)
	l.RulesApplied("abc123", "name", []net.IP{net.IPv4(1, 2, 3, 4)}, 2, "deny", SourceEvent)
	if len(cs.events) != 1 {
		t.Fatalf("events = %d", len(cs.events))
	}
	ev := cs.events[0]
	if ev.Action != "apply" || ev.ContainerID != "abc123" || ev.RuleSets != 2 {
		t.Errorf("event = %+v", ev)
	}
	if len(ev.ContainerIPs) != 1 || ev.ContainerIPs[0] != "1.2.3.4" {
		t.Errorf("ips = %v", ev.ContainerIPs)
	}
}

func TestRulesRemoved(t *testing.T) {
	cs := &logCaptureSink{}
	l := newTestLogger().WithSink(cs)
	l.RulesRemoved("abc123", SourceManual)
	if len(cs.events) != 1 || cs.events[0].Action != "remove" {
		t.Errorf("events = %+v", cs.events)
	}
}

func TestLegacyCleanup(t *testing.T) {
	cs := &logCaptureSink{}
	l := newTestLogger().WithSink(cs)
	l.LegacyCleanup("FIREFIK-v0", "v0", 3, "")
	if cs.events[0].Action != "cleanup_legacy" {
		t.Errorf("got %+v", cs.events[0])
	}
	if cs.events[0].RuleSets != 3 {
		t.Errorf("count = %d", cs.events[0].RuleSets)
	}
}

func TestLegacyCleanupWithError(t *testing.T) {
	cs := &logCaptureSink{}
	l := newTestLogger().WithSink(cs)
	l.LegacyCleanup("FIREFIK-v0", "v0", 0, "boom")
	if cs.events[0].Metadata["error"] != "boom" {
		t.Errorf("missing error: %+v", cs.events[0].Metadata)
	}
}

func TestTokenRotated(t *testing.T) {
	cs := &logCaptureSink{}
	l := newTestLogger().WithSink(cs)
	l.TokenRotated("fp123")
	if cs.events[0].Action != "token_rotated" || cs.events[0].Metadata["fingerprint"] != "fp123" {
		t.Errorf("got %+v", cs.events[0])
	}
}

func TestDriftDetected(t *testing.T) {
	cs := &logCaptureSink{}
	l := newTestLogger().WithSink(cs)
	l.DriftDetected("orphans", map[string]int{"count": 5})
	if cs.events[0].Action != "drift_detected" {
		t.Errorf("got %+v", cs.events[0])
	}
	if cs.events[0].Metadata["count"] != "5" {
		t.Errorf("metadata = %+v", cs.events[0].Metadata)
	}
}

func TestPolicyUpdated(t *testing.T) {
	cs := &logCaptureSink{}
	l := newTestLogger().WithSink(cs)
	l.PolicyUpdated("p1", "v2", "comment", "api")
	if cs.events[0].Action != "policy_updated" {
		t.Errorf("got %+v", cs.events[0])
	}
	if cs.events[0].Metadata["comment"] != "comment" {
		t.Errorf("metadata = %+v", cs.events[0].Metadata)
	}
}

func TestPolicyUpdatedNoComment(t *testing.T) {
	cs := &logCaptureSink{}
	l := newTestLogger().WithSink(cs)
	l.PolicyUpdated("p1", "v2", "", "api")
	if _, ok := cs.events[0].Metadata["comment"]; ok {
		t.Errorf("should not have comment metadata")
	}
}

func TestAutogenApproved(t *testing.T) {
	cs := &logCaptureSink{}
	l := newTestLogger().WithSink(cs)
	l.AutogenApproved("abc123", "name", []uint16{80, 443}, []string{"1.2.3.4"}, "label", "alice")
	if cs.events[0].Action != "autogen_approved" {
		t.Errorf("got %+v", cs.events[0])
	}
	if cs.events[0].Metadata["author"] != "alice" {
		t.Errorf("metadata = %+v", cs.events[0].Metadata)
	}
}

func TestAutogenRejected(t *testing.T) {
	cs := &logCaptureSink{}
	l := newTestLogger().WithSink(cs)
	l.AutogenRejected("abc123", "name", "noisy", "alice")
	if cs.events[0].Action != "autogen_rejected" {
		t.Errorf("got %+v", cs.events[0])
	}
}

func TestReconcileStarted(t *testing.T) {
	cs := &logCaptureSink{}
	l := newTestLogger().WithSink(cs)
	l.ReconcileStarted(SourceStartup)
	if cs.events[0].Action != "reconcile" {
		t.Errorf("got %+v", cs.events[0])
	}
}

func TestHistoryBufferClose(t *testing.T) {
	hb := NewHistoryBuffer(5)
	if err := hb.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestNewHistoryBufferZeroSize(t *testing.T) {
	hb := NewHistoryBuffer(0)
	if hb == nil {
		t.Errorf("nil")
	}
}
