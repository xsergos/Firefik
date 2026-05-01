package controlplane

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestStreamLogs_DeliversPublishedLines(t *testing.T) {
	store := NewMemoryStore()
	srv := &HTTPServer{
		Registry: NewRegistryWithStore(slog.New(slog.NewTextHandler(io.Discard, nil)), store),
		Token:    "secret",
	}
	if err := store.UpsertAgent(t.Context(), AgentIdentity{InstanceID: "h1", Hostname: "h1"}); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/agents/h1/logs"
	headers := http.Header{}
	headers.Set("Authorization", "Bearer secret")

	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		body := ""
		if resp != nil {
			b, _ := io.ReadAll(resp.Body)
			body = string(b)
		}
		t.Fatalf("dial: %v status=%v body=%s", err, resp, body)
	}
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	srv.Registry.PublishLog(LogLine{
		Agent: AgentIdentity{InstanceID: "h1", Hostname: "h1"},
		At:    time.Now(),
		Level: "info",
		Line:  "hello",
	})

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got LogLine
	if err := json.Unmarshal(msg, &got); err != nil {
		t.Fatalf("decode: %v body=%s", err, msg)
	}
	if got.Line != "hello" || got.Level != "info" {
		t.Fatalf("got %+v", got)
	}
}

func TestStreamLogs_RequiresBearer(t *testing.T) {
	srv := &HTTPServer{
		Registry: NewRegistryWithStore(slog.New(slog.NewTextHandler(io.Discard, nil)), NewMemoryStore()),
		Token:    "secret",
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/agents/h1/logs"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("expected dial to fail without auth")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %v", resp)
	}
}
