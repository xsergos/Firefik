package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewControlPlaneProxy_RequiresBaseURL(t *testing.T) {
	if _, err := NewControlPlaneProxy("", "", "", false); err == nil {
		t.Fatal("expected error")
	}
}

func TestNewControlPlaneProxy_BadCAFile(t *testing.T) {
	if _, err := NewControlPlaneProxy("http://x", "", "/no/such/file", false); err == nil {
		t.Fatal("expected error for missing CA")
	}
}

func TestNewControlPlaneProxy_InvalidPEM(t *testing.T) {
	tmp := t.TempDir() + "/bad.pem"
	if err := writeFile(tmp, "not a pem"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewControlPlaneProxy("http://x", "", tmp, false); err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestControlPlaneProxy_Forward(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer up-token" {
			http.Error(w, "no token", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"path":"` + r.URL.Path + `","method":"` + r.Method + `","body":"` + string(body) + `"}`))
	}))
	defer upstream.Close()

	p, err := NewControlPlaneProxy(upstream.URL, "up-token", "", false)
	if err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/v1/templates", p.handleTemplatesList)
	r.POST("/v1/templates", p.handleTemplatePublish)
	r.GET("/v1/approvals/:id", p.handleApprovalGet)
	r.POST("/v1/approvals/:id/approve", p.handleApprovalApprove)
	r.POST("/v1/approvals/:id/reject", p.handleApprovalReject)
	r.POST("/v1/approvals", p.handleApprovalCreate)
	r.GET("/v1/approvals", p.handleApprovalsList)
	r.GET("/v1/templates/:name", p.handleTemplateGet)

	cases := []struct {
		method, path, body string
		wantPath           string
	}{
		{"GET", "/v1/templates", "", "/v1/templates"},
		{"POST", "/v1/templates", `{"name":"x"}`, "/v1/templates"},
		{"GET", "/v1/templates/foo", "", "/v1/templates/foo"},
		{"GET", "/v1/approvals", "", "/v1/approvals"},
		{"POST", "/v1/approvals", `{}`, "/v1/approvals"},
		{"GET", "/v1/approvals/abc", "", "/v1/approvals/abc"},
		{"POST", "/v1/approvals/abc/approve", `{}`, "/v1/approvals/abc/approve"},
		{"POST", "/v1/approvals/abc/reject", `{}`, "/v1/approvals/abc/reject"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("%s %s: code=%d body=%s", tc.method, tc.path, rr.Code, rr.Body.String())
			continue
		}
		if !strings.Contains(rr.Body.String(), tc.wantPath) {
			t.Errorf("%s %s: missing %q in %s", tc.method, tc.path, tc.wantPath, rr.Body.String())
		}
	}
}

func TestControlPlaneProxy_UpstreamUnreachable(t *testing.T) {
	p, err := NewControlPlaneProxy("http://127.0.0.1:1", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/x", p.handleTemplatesList)
	req := httptest.NewRequest("GET", "/x", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rr.Code)
	}
}

func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}
