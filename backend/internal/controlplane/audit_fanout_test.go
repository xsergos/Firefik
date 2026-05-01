package controlplane

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"firefik/internal/audit"
)

type captureSink struct {
	events []audit.Event
	err    error
}

func (c *captureSink) Write(ev audit.Event) error {
	c.events = append(c.events, ev)
	return c.err
}

func (c *captureSink) Close() error { return nil }

func TestSinkFanOut_EmitForwardsToAllSinks(t *testing.T) {
	a := &captureSink{}
	b := &captureSink{}
	f := &SinkFanOut{Sinks: []audit.Sink{a, b}}
	f.Emit("policy_approval_requested", map[string]string{"approval_id": "x"})
	if len(a.events) != 1 || len(b.events) != 1 {
		t.Fatalf("a=%d b=%d", len(a.events), len(b.events))
	}
	if a.events[0].Action != "policy_approval_requested" {
		t.Errorf("action = %q", a.events[0].Action)
	}
	if a.events[0].Source != audit.SourceControlPlane {
		t.Errorf("source = %q", a.events[0].Source)
	}
	if a.events[0].Metadata["approval_id"] != "x" {
		t.Errorf("metadata = %v", a.events[0].Metadata)
	}
}

func TestSinkFanOut_EmitNoSinksNoOp(t *testing.T) {
	f := &SinkFanOut{}
	f.Emit("x", nil)
	var nilFan *SinkFanOut
	nilFan.Emit("x", nil)
}

func TestSinkFanOut_LogsErrorOnSinkFailure(t *testing.T) {
	bad := &captureSink{err: errors.New("boom")}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	f := &SinkFanOut{Sinks: []audit.Sink{bad}, Logger: logger}
	f.Emit("x", nil)
	if len(bad.events) != 1 {
		t.Errorf("expected event recorded even on error")
	}
}

func TestHTTPHandlers_ApprovalEventsEmitted(t *testing.T) {
	store := NewMemoryStore()
	cap := &captureSink{}
	srv := &HTTPServer{
		Registry: NewRegistryWithStore(slog.New(slog.NewTextHandler(io.Discard, nil)), store),
		Token:    "secret",
		Audit:    &SinkFanOut{Sinks: []audit.Sink{cap}},
	}
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/approvals",
		strings.NewReader(`{"policy_name":"p","proposed_body":"b","requester":"alice"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	if len(cap.events) != 1 || cap.events[0].Action != "policy_approval_requested" {
		t.Errorf("requested event = %+v", cap.events)
	}

	if _, err := store.CreateApproval(context.Background(), PendingApproval{
		ID: "fixture", PolicyName: "p", ProposedBody: "b", Requester: "alice", RequesterFinger: "fp-other",
	}); err != nil {
		t.Fatal(err)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/approvals/fixture/approve",
		strings.NewReader(`{"approver":"bob"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body.String())
	}
	if len(cap.events) != 2 || cap.events[1].Action != "policy_approval_approved" {
		t.Errorf("approve event = %+v", cap.events[1])
	}

	if _, err := store.CreateApproval(context.Background(), PendingApproval{
		ID: "f2", PolicyName: "p", ProposedBody: "b2", Requester: "alice", RequesterFinger: "fp-other",
	}); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/approvals/f2/reject",
		strings.NewReader(`{"approver":"bob","comment":"nope"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("reject: %d %s", rr.Code, rr.Body.String())
	}
	if len(cap.events) != 3 || cap.events[2].Action != "policy_approval_rejected" {
		t.Errorf("reject event = %+v", cap.events[2])
	}
	if cap.events[2].Metadata["comment"] != "nope" {
		t.Errorf("comment metadata = %q", cap.events[2].Metadata["comment"])
	}
}

func TestHTTPHandlers_NoAuditNoEvents(t *testing.T) {
	store := NewMemoryStore()
	srv := &HTTPServer{
		Registry: NewRegistryWithStore(slog.New(slog.NewTextHandler(io.Discard, nil)), store),
		Token:    "secret",
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals",
		strings.NewReader(`{"policy_name":"p","proposed_body":"b","requester":"alice"}`))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("code = %d", rr.Code)
	}
}
