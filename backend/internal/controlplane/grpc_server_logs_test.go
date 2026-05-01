package controlplane

import (
	"io"
	"log/slog"
	"testing"
	"time"

	pb "firefik/internal/controlplane/gen/controlplanev1"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHandleEvent_LogLineFanoutsToHub(t *testing.T) {
	reg := NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)))
	s := &GRPCServer{Registry: reg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	sub := reg.LogHub().Subscribe("h1")
	defer sub.Close()

	ev := &pb.AgentEvent{
		Kind: &pb.AgentEvent_Log{
			Log: &pb.LogLine{
				Agent:  &pb.AgentIdentity{InstanceId: "h1", Hostname: "h1"},
				At:     timestamppb.New(time.Now()),
				Level:  "info",
				Source: "audit",
				Line:   "rules applied",
				Fields: map[string]string{"action": "apply"},
			},
		},
	}
	s.handleEvent(ev)

	select {
	case got := <-sub.C():
		if got.Line != "rules applied" || got.Source != "audit" || got.Level != "info" {
			t.Fatalf("unexpected: %+v", got)
		}
		if got.Fields["action"] != "apply" {
			t.Fatalf("fields not propagated: %+v", got.Fields)
		}
		if got.Agent.InstanceID != "h1" {
			t.Fatalf("agent identity lost: %+v", got.Agent)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestHandleEvent_LogLineUpsertsAgent(t *testing.T) {
	reg := NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)))
	s := &GRPCServer{Registry: reg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	ev := &pb.AgentEvent{
		Kind: &pb.AgentEvent_Log{
			Log: &pb.LogLine{
				Agent: &pb.AgentIdentity{InstanceId: "newhost", Hostname: "newhost"},
				Line:  "x",
			},
		},
	}
	s.handleEvent(ev)

	agents := reg.Agents()
	found := false
	for _, a := range agents {
		if a.Identity.InstanceID == "newhost" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("agent not registered after log event: %+v", agents)
	}
}

func TestHandleEvent_LogLineNilSafeguards(t *testing.T) {
	reg := NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)))
	s := &GRPCServer{Registry: reg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.handleEvent(&pb.AgentEvent{Kind: &pb.AgentEvent_Log{Log: nil}})
	s.handleEvent(&pb.AgentEvent{Kind: &pb.AgentEvent_Log{Log: &pb.LogLine{Agent: nil}}})
}

func TestAgentIDFromEvent_Log(t *testing.T) {
	ev := &pb.AgentEvent{
		Kind: &pb.AgentEvent_Log{
			Log: &pb.LogLine{Agent: &pb.AgentIdentity{InstanceId: "h-log"}},
		},
	}
	id, ok := agentIDFromEvent(ev)
	if !ok || id != "h-log" {
		t.Fatalf("got (%q,%v)", id, ok)
	}
}
