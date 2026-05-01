package audit

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemoteSink_HappyPath(t *testing.T) {
	var received int32
	var mu sync.Mutex
	var bodies []string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	sink, err := NewRemoteSink(RemoteSinkOptions{
		Endpoint:   ts.URL,
		BufferSize: 100,
		Timeout:    2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewRemoteSink: %v", err)
	}

	if err := sink.Write(Event{Action: "apply", ContainerID: "abc"}); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&received) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&received) < 1 {
		t.Fatalf("expected 1 POST, got %d", received)
	}

	mu.Lock()
	body := bodies[0]
	mu.Unlock()
	if !strings.Contains(body, `"action":"apply"`) {
		t.Errorf("body missing action field: %q", body)
	}
	var ev Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &ev); err != nil {
		t.Errorf("ndjson not valid JSON event: %v", err)
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestRemoteSink_RequiresEndpoint(t *testing.T) {
	_, err := NewRemoteSink(RemoteSinkOptions{})
	if err == nil {
		t.Fatal("want error when endpoint is empty")
	}
	if !strings.Contains(err.Error(), "endpoint is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRemoteSink_DropsOnFullBuffer(t *testing.T) {

	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer ts.Close()
	defer close(release)

	sink, err := NewRemoteSink(RemoteSinkOptions{
		Endpoint:   ts.URL,
		BufferSize: 2,
		Timeout:    200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewRemoteSink: %v", err)
	}
	defer sink.Close()

	for i := 0; i < 100; i++ {
		if err := sink.Write(Event{Action: "apply"}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	rs, ok := sink.(*remoteSink)
	if !ok {
		t.Fatalf("unexpected sink type %T", sink)
	}
	rs.mu.Lock()
	dropped := rs.dropped
	rs.mu.Unlock()
	if dropped == 0 {
		t.Errorf("expected some events to be dropped, got 0")
	}
}
