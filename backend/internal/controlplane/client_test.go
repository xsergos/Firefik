package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewEnrollClient(t *testing.T) {
	c := NewEnrollClient("https://x", "tok")
	if c.Endpoint != "https://x" || c.Token != "tok" || c.HTTP == nil {
		t.Errorf("unexpected: %+v", c)
	}
}

func TestEnrollSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no auth", 401)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad ct", 400)
			return
		}
		w.Write([]byte(`{"cert_pem":"C","key_pem":"K","bundle_pem":"B","serial":"1","spiffe_uri":"spiffe://x","not_after_unix":1234}`))
	}))
	defer srv.Close()
	c := NewEnrollClient(srv.URL, "tok")
	resp, err := c.Enroll(context.Background(), EnrollRequest{AgentID: "a", TTLSeconds: 3600})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp.CertPEM != "C" || resp.NotAfterUnix != 1234 {
		t.Errorf("unexpected: %+v", resp)
	}
}

func TestEnrollServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", 500)
	}))
	defer srv.Close()
	c := NewEnrollClient(srv.URL, "")
	if _, err := c.Enroll(context.Background(), EnrollRequest{AgentID: "a"}); err == nil {
		t.Errorf("expected error")
	}
}

func TestEnrollBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()
	c := NewEnrollClient(srv.URL, "")
	if _, err := c.Enroll(context.Background(), EnrollRequest{AgentID: "a"}); err == nil {
		t.Errorf("expected error")
	}
}

func TestEnrollTransportError(t *testing.T) {
	c := NewEnrollClient("http://127.0.0.1:1", "")
	if _, err := c.Enroll(context.Background(), EnrollRequest{AgentID: "a"}); err == nil {
		t.Errorf("expected transport error")
	}
}

func TestEnrollBadURL(t *testing.T) {
	c := NewEnrollClient("://invalid", "")
	if _, err := c.Enroll(context.Background(), EnrollRequest{AgentID: "a"}); err == nil {
		t.Errorf("expected error")
	}
}

func TestEnrollNoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get("Authorization"); v != "" {
			t.Errorf("expected no auth header, got %q", v)
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := NewEnrollClient(srv.URL, "")
	if _, err := c.Enroll(context.Background(), EnrollRequest{AgentID: "a"}); err != nil {
		t.Errorf("err: %v", err)
	}
}

var _ = strings.Contains
