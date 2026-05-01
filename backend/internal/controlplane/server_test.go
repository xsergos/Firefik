package controlplane

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthzPublic(t *testing.T) {
	srv := &HTTPServer{}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz should be 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("healthz body = %q", string(body))
	}
}

func TestEnrollHandlerInvoked(t *testing.T) {
	called := 0
	srv := &HTTPServer{
		EnrollHandle: func(w http.ResponseWriter, r *http.Request) {
			called++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		},
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/v1/enroll", "application/json", strings.NewReader(`{"agent_id":"a"}`))
	if err != nil {
		t.Fatalf("enroll POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if called != 1 {
		t.Errorf("enroll handler not invoked (called=%d)", called)
	}
}

func TestEnrollUnregisteredReturns404(t *testing.T) {
	srv := &HTTPServer{}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/v1/enroll", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("enroll POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("want 404 when enroll handler not wired, got %d", resp.StatusCode)
	}
}
