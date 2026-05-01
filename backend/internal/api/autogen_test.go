package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"firefik/internal/autogen"
	"firefik/internal/config"
)

func TestShortIDInternal(t *testing.T) {
	if got := shortID("abc"); got != "abc" {
		t.Errorf("got %q", got)
	}
	if got := shortID("abcdefghijklmnop"); got != "abcdefghijkl" {
		t.Errorf("got %q", got)
	}
}

func TestProposalToLabels(t *testing.T) {
	p := autogen.Proposal{
		ContainerID: "abc",
		Ports:       []uint16{80, 443},
		Peers:       []string{"10.0.0.1", "10.0.0.2"},
	}
	got := proposalToLabels(p)
	if !strings.Contains(got, "firefik.enable") {
		t.Errorf("missing enable: %s", got)
	}
	if !strings.Contains(got, "80,443") {
		t.Errorf("missing ports: %s", got)
	}
	if !strings.Contains(got, "10.0.0.1,10.0.0.2") {
		t.Errorf("missing peers: %s", got)
	}
}

func TestProposalToLabelsEmpty(t *testing.T) {
	p := autogen.Proposal{ContainerID: "abc"}
	got := proposalToLabels(p)
	if !strings.Contains(got, "firefik.enable") {
		t.Errorf("missing: %s", got)
	}
}

func TestProposalToPolicyDSL(t *testing.T) {
	p := autogen.Proposal{
		ContainerID: "abc123def456",
		Ports:       []uint16{80, 443},
		Peers:       []string{"10.0.0.1"},
	}
	got := proposalToPolicyDSL(p)
	if !strings.Contains(got, "policy ") {
		t.Errorf("missing policy: %s", got)
	}
	if !strings.Contains(got, "80, 443") {
		t.Errorf("missing ports: %s", got)
	}
	if !strings.Contains(got, "10.0.0.1") {
		t.Errorf("missing peer: %s", got)
	}
}

func TestRecordsToDTOMergesLiveAndStored(t *testing.T) {
	live := []autogen.Proposal{
		{ContainerID: "a1", Ports: []uint16{80}, Confidence: "high"},
		{ContainerID: "b2", Ports: []uint16{443}, Confidence: "low"},
	}
	records := []autogen.ProposalRecord{
		{ContainerID: "a1", Status: autogen.StatusApproved, DecidedBy: "alice"},
		{ContainerID: "old", Status: autogen.StatusRejected, Reason: "noisy"},
	}
	got := recordsToDTO(live, records)
	if len(got) != 3 {
		t.Errorf("len = %d", len(got))
	}
	for _, dto := range got {
		if dto.ContainerID == "a1" && dto.DecidedBy != "alice" {
			t.Errorf("a1 missing decided_by: %+v", dto)
		}
	}
}

func TestHandleGetAutogenProposalsDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.GET("/p", s.handleGetAutogenProposals)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/p", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "[]") {
		t.Errorf("expected empty array, got %q", rec.Body.String())
	}
}

func TestHandleApproveAutogenDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.POST("/a/:id", s.handleApproveAutogen)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/a/abc", strings.NewReader(`{}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestHandleApproveAutogenInvalidMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	s.SetAutogen(autogen.NewObserver())
	r := gin.New()
	r.POST("/a/:id", s.handleApproveAutogen)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/a/abc", strings.NewReader(`{"mode":"voodoo"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleApproveAutogenNoProposal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	s.SetAutogen(autogen.NewObserver())
	r := gin.New()
	r.POST("/a/:id", s.handleApproveAutogen)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/a/abc", strings.NewReader(`{"mode":"labels"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleRejectAutogenDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	r := gin.New()
	r.POST("/r/:id", s.handleRejectAutogen)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/r/abc", strings.NewReader(`{}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestHandleRejectAutogenSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	obs := autogen.NewObserver()
	s.SetAutogen(obs)
	r := gin.New()
	r.POST("/r/:id", s.handleRejectAutogen)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/r/abc", strings.NewReader(`{"reason":"noisy"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent && rec.Code != http.StatusInternalServerError {
		t.Errorf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleGetAutogenProposalsActiveObserver(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{AutogenMinSamples: 1}
	s := makeTestServer(t, cfg)
	obs := autogen.NewObserver()
	s.SetAutogen(obs)
	r := gin.New()
	r.GET("/p", s.handleGetAutogenProposals)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/p", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code=%d", rec.Code)
	}
}

func TestHandleApproveAutogenEmptyID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	obs := autogen.NewObserver()
	s.SetAutogen(obs)
	r := gin.New()
	r.POST("/a/:id", s.handleApproveAutogen)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/a/", strings.NewReader(`{"mode":"labels"}`))
	r.ServeHTTP(rec, req)
}

func TestHandleRejectAutogenEmptyID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{}
	s := makeTestServer(t, cfg)
	obs := autogen.NewObserver()
	s.SetAutogen(obs)
	r := gin.New()
	r.POST("/r/:id", s.handleRejectAutogen)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/r/", strings.NewReader(`{}`))
	r.ServeHTTP(rec, req)
}
