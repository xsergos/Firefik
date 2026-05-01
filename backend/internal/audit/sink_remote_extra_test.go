package audit

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemoteSinkRetry(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n < 3 {
			http.Error(w, "transient", 500)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	sink, err := NewRemoteSink(RemoteSinkOptions{
		Endpoint:     ts.URL,
		BufferSize:   10,
		Timeout:      500 * time.Millisecond,
		RetryBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	if err := sink.Write(Event{Action: "apply"}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&hits) >= 3 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRemoteSinkExhaustsRetries(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "always fails", 500)
	}))
	defer ts.Close()

	sink, err := NewRemoteSink(RemoteSinkOptions{
		Endpoint:     ts.URL,
		BufferSize:   10,
		Timeout:      100 * time.Millisecond,
		RetryBackoff: 1 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := sink.Write(Event{Action: "apply"}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond)

	rs := sink.(*remoteSink)
	rs.mu.Lock()
	d := rs.dropped
	rs.mu.Unlock()
	if d == 0 {
		t.Errorf("expected dropped count > 0, got %d", d)
	}
	_ = sink.Close()
}
