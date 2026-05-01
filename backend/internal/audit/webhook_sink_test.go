package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebhookSink_RequiresURL(t *testing.T) {
	_, err := NewWebhookSink(WebhookOptions{})
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestWebhookSink_HappyPath(t *testing.T) {
	var calls int32
	var mu sync.Mutex
	var gotBody []byte
	var gotHeaders http.Header

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = b
		gotHeaders = r.Header.Clone()
		mu.Unlock()
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	sink, err := NewWebhookSink(WebhookOptions{
		URL:     ts.URL,
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}
	defer sink.Close()

	ev := Event{Action: "rule_applied", ContainerID: "abc"}
	if err := sink.Write(ev); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 POST, got %d", got)
	}

	mu.Lock()
	body := gotBody
	hdrs := gotHeaders
	mu.Unlock()

	if ct := hdrs.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if ev := hdrs.Get("X-Firefik-Event"); ev != "rule_applied" {
		t.Errorf("X-Firefik-Event = %q, want rule_applied", ev)
	}
	if sig := hdrs.Get("X-Firefik-Signature"); sig != "" {
		t.Errorf("X-Firefik-Signature should be empty without secret, got %q", sig)
	}

	var decoded Event
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body is not valid JSON Event: %v", err)
	}
	if decoded.Action != "rule_applied" {
		t.Errorf("decoded.Action = %q, want rule_applied", decoded.Action)
	}
}

func TestWebhookSink_WhitelistFilter(t *testing.T) {
	var calls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	sink, err := NewWebhookSink(WebhookOptions{
		URL:    ts.URL,
		Events: []string{"rule_applied", "policy_changed"},
	})
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}
	defer sink.Close()

	if err := sink.Write(Event{Action: "some_other_event"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected 0 POSTs for non-whitelisted event, got %d", got)
	}

	if err := sink.Write(Event{Action: "rule_applied"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 POST for whitelisted event, got %d", got)
	}
}

func TestWebhookSink_EmptyWhitelistAllowsAll(t *testing.T) {
	var calls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	sink, err := NewWebhookSink(WebhookOptions{URL: ts.URL})
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}
	defer sink.Close()

	for _, a := range []string{"a", "b", "c"} {
		if err := sink.Write(Event{Action: a}); err != nil {
			t.Fatalf("write %s: %v", a, err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("expected 3 POSTs with empty whitelist, got %d", got)
	}
}

func TestWebhookSink_HMACSignature(t *testing.T) {
	secret := "s3cret-key"
	var mu sync.Mutex
	var gotBody []byte
	var gotSig string

	var gotAction string
	var gotTS string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = b
		gotSig = r.Header.Get("X-Firefik-Signature")
		gotAction = r.Header.Get("X-Firefik-Event")
		gotTS = r.Header.Get("X-Firefik-Timestamp")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	sink, err := NewWebhookSink(WebhookOptions{
		URL:    ts.URL,
		Secret: secret,
	})
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}
	defer sink.Close()

	ev := Event{Action: "rule_applied", ContainerID: "xyz"}
	if err := sink.Write(ev); err != nil {
		t.Fatalf("write: %v", err)
	}

	mu.Lock()
	body := gotBody
	sig := gotSig
	action := gotAction
	tsHdr := gotTS
	mu.Unlock()

	if sig == "" {
		t.Fatal("expected X-Firefik-Signature header when secret set")
	}
	if tsHdr == "" {
		t.Fatal("expected X-Firefik-Timestamp header for replay protection")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(action))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(tsHdr))
	mac.Write([]byte{'\n'})
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sig != want {
		t.Errorf("signature mismatch:\n got: %s\nwant: %s", sig, want)
	}
}

func TestWebhookSink_RetryOn5xx(t *testing.T) {
	var calls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	sink, err := NewWebhookSink(WebhookOptions{URL: ts.URL})
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}
	defer sink.Close()

	if err := sink.Write(Event{Action: "rule_applied"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 POSTs (one retry on 5xx), got %d", got)
	}
}

func TestWebhookSink_No4xxRetry(t *testing.T) {
	var calls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	sink, err := NewWebhookSink(WebhookOptions{URL: ts.URL})
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}
	defer sink.Close()

	if err := sink.Write(Event{Action: "rule_applied"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 POST (no retry on 4xx), got %d", got)
	}
}

func TestWebhookSink_ConnectionRefusedDropsSilently(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	url := ts.URL
	ts.Close()

	sink, err := NewWebhookSink(WebhookOptions{
		URL:     url,
		Timeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}
	defer sink.Close()

	if err := sink.Write(Event{Action: "rule_applied"}); err != nil {
		t.Fatalf("write should not bubble up connection errors: %v", err)
	}
}

func TestWebhookSink_DefaultTimeoutApplied(t *testing.T) {
	sink, err := NewWebhookSink(WebhookOptions{URL: "http://example.invalid"})
	if err != nil {
		t.Fatalf("NewWebhookSink: %v", err)
	}
	defer sink.Close()

	ws, ok := sink.(*WebhookSink)
	if !ok {
		t.Fatalf("unexpected type %T", sink)
	}
	if ws.client.Timeout != 5*time.Second {
		t.Errorf("default timeout = %v, want 5s", ws.client.Timeout)
	}
}
