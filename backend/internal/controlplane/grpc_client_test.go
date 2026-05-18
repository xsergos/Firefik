package controlplane

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	pb "firefik/internal/controlplane/gen/controlplanev1"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSleepWithContextNormal(t *testing.T) {
	if !sleepWithContext(context.Background(), 1*time.Millisecond) {
		t.Errorf("expected true")
	}
}

func TestSleepWithContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepWithContext(ctx, 1*time.Hour) {
		t.Errorf("expected false on cancelled context")
	}
}

func TestNextBackoffDoubles(t *testing.T) {
	got := nextBackoff(backoffMin)
	if got != 2*backoffMin {
		t.Errorf("got %v, want %v", got, 2*backoffMin)
	}
}

func TestNextBackoffCapsAtMax(t *testing.T) {
	got := nextBackoff(backoffMax)
	if got != backoffMax {
		t.Errorf("got %v, want %v", got, backoffMax)
	}
}

func TestJitterReturnsBoundedValue(t *testing.T) {
	for i := 0; i < 100; i++ {
		got := jitter(time.Second)
		if got < backoffMin {
			t.Errorf("got %v < min %v", got, backoffMin)
		}
	}
}

func TestJitterPreservesMin(t *testing.T) {
	got := jitter(0)
	if got < backoffMin {
		t.Errorf("got %v < min %v", got, backoffMin)
	}
}

func TestToPBIdentity(t *testing.T) {
	in := AgentIdentity{
		InstanceID: "id1",
		Hostname:   "h",
		Version:    "v1",
		Backend:    "nft",
		Chain:      "F",
		Labels:     map[string]string{"a": "b"},
	}
	out := toPBIdentity(in)
	if out.InstanceId != "id1" || out.Hostname != "h" || out.Labels["a"] != "b" {
		t.Errorf("unexpected: %+v", out)
	}
}

func TestToPBSnapshot(t *testing.T) {
	in := AgentSnapshot{
		Agent: AgentIdentity{InstanceID: "id1"},
		At:    time.Now(),
		Containers: []ContainerState{
			{ID: "c1", Name: "n1", Status: "running", FirewallStatus: "active", DefaultPolicy: "deny", Labels: map[string]string{"x": "y"}, RuleSetCount: 3},
		},
	}
	out := toPBSnapshot(in)
	if len(out.Containers) != 1 || out.Containers[0].Id != "c1" || out.Containers[0].RuleSetCount != 3 {
		t.Errorf("unexpected: %+v", out)
	}
}

func TestToPBAck(t *testing.T) {
	in := CommandAck{ID: "i", AgentID: "a", Success: true, Error: "", CompletedAt: time.Now()}
	out := toPBAck(in)
	if out.Id != "i" || !out.Success {
		t.Errorf("unexpected: %+v", out)
	}
}

func TestToPBAck_WithResultPayload(t *testing.T) {
	in := CommandAck{
		ID:            "id-1",
		AgentID:       "agent-1",
		Success:       true,
		CompletedAt:   time.Now(),
		ResultPayload: map[string]any{"mode": "labels", "ports": []any{80.0, 443.0}},
	}
	out := toPBAck(in)
	if out.ResultPayload == nil {
		t.Fatal("ResultPayload should be set")
	}
	if got := out.ResultPayload.Fields["mode"].GetStringValue(); got != "labels" {
		t.Errorf("mode=%q", got)
	}
}

func TestToPBAck_InvalidPayloadDropped(t *testing.T) {
	in := CommandAck{
		ID:            "id-1",
		Success:       false,
		Error:         "boom",
		CompletedAt:   time.Now(),
		ResultPayload: map[string]any{"bad": make(chan int)},
	}
	out := toPBAck(in)
	if out.ResultPayload != nil {
		t.Errorf("invalid payload should be dropped, got %+v", out.ResultPayload)
	}
	if out.Error != "boom" {
		t.Errorf("error: %q", out.Error)
	}
}

func TestToNativeCommand(t *testing.T) {
	in := &pb.ServerCommand{
		Id:          "cmd1",
		Kind:        pb.CommandKind_COMMAND_KIND_APPLY,
		ContainerId: "c1",
	}
	out := toNativeCommand(in)
	if out.ID != "cmd1" || out.Kind != CommandApply {
		t.Errorf("unexpected: %+v", out)
	}
}

func TestCommandKindFromPB(t *testing.T) {
	cases := map[pb.CommandKind]CommandKind{
		pb.CommandKind_COMMAND_KIND_APPLY:        CommandApply,
		pb.CommandKind_COMMAND_KIND_DISABLE:      CommandDisable,
		pb.CommandKind_COMMAND_KIND_RECONCILE:    CommandReconcile,
		pb.CommandKind_COMMAND_KIND_TOKEN_ROTATE: CommandTokenRotate,
	}
	for in, want := range cases {
		if got := commandKindFromPB(in); got != want {
			t.Errorf("commandKindFromPB(%v) = %v, want %v", in, got, want)
		}
	}
	if got := commandKindFromPB(pb.CommandKind(99)); got != "" {
		t.Errorf("unknown kind should yield empty, got %q", got)
	}
}

func TestNewGRPCClientDefaultsTimeout(t *testing.T) {
	c := NewGRPCClient(GRPCClientConfig{})
	if c.cfg.DialTimeout == 0 {
		t.Errorf("expected default")
	}
}

func TestNewGRPCClientPreservesTimeout(t *testing.T) {
	c := NewGRPCClient(GRPCClientConfig{DialTimeout: 100 * time.Millisecond})
	if c.cfg.DialTimeout != 100*time.Millisecond {
		t.Errorf("got %v", c.cfg.DialTimeout)
	}
}

func TestSendSnapshotStreamDown(t *testing.T) {
	c := NewGRPCClient(GRPCClientConfig{})
	if err := c.SendSnapshot(AgentSnapshot{}); !errors.Is(err, ErrStreamDown) {
		t.Errorf("got %v, want ErrStreamDown", err)
	}
}

func TestSendAuditStreamDown(t *testing.T) {
	c := NewGRPCClient(GRPCClientConfig{})
	if err := c.SendAudit(map[string]any{"k": "v"}); !errors.Is(err, ErrStreamDown) {
		t.Errorf("got %v, want ErrStreamDown", err)
	}
}

func TestSendHeartbeatStreamDown(t *testing.T) {
	c := NewGRPCClient(GRPCClientConfig{})
	if err := c.SendHeartbeat(); !errors.Is(err, ErrStreamDown) {
		t.Errorf("got %v, want ErrStreamDown", err)
	}
}

func TestSendAutogenProposals_EmptyIsNoop(t *testing.T) {
	c := NewGRPCClient(GRPCClientConfig{})
	if err := c.SendAutogenProposals(nil); err != nil {
		t.Errorf("nil items: %v", err)
	}
	if err := c.SendAutogenProposals([]AutogenProposal{}); err != nil {
		t.Errorf("empty items: %v", err)
	}
}

func TestSendAutogenProposals_StreamDown(t *testing.T) {
	c := NewGRPCClient(GRPCClientConfig{})
	err := c.SendAutogenProposals([]AutogenProposal{
		{ContainerID: "c1", Ports: []uint32{80}, Peers: []string{"10.0.0.0/8"}},
	})
	if !errors.Is(err, ErrStreamDown) {
		t.Errorf("got %v, want ErrStreamDown", err)
	}
}

func TestWithAuthEmptyToken(t *testing.T) {
	ctx := context.Background()
	got := withAuth(ctx, "")
	if got != ctx {
		t.Errorf("expected unchanged context")
	}
}

func TestWithAuthWithToken(t *testing.T) {
	ctx := context.Background()
	got := withAuth(ctx, "secret")
	if got == ctx {
		t.Errorf("expected modified context")
	}
}

func TestRunCancelImmediately(t *testing.T) {
	c := NewGRPCClient(GRPCClientConfig{
		Endpoint:    "127.0.0.1:1",
		DialTimeout: 50 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Run(ctx); err != nil {
		t.Errorf("expected nil on canceled ctx, got %v", err)
	}
}

func TestToNativeCommandPayloadAndIssuedAt(t *testing.T) {
	now := time.Now()
	st, err := structpb.NewStruct(map[string]any{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	in := &pb.ServerCommand{
		Id:          "x",
		Kind:        pb.CommandKind_COMMAND_KIND_RECONCILE,
		ContainerId: "c",
		IssuedAt:    timestamppb.New(now),
		Payload:     st,
	}
	out := toNativeCommand(in)
	if out.IssuedAt.IsZero() {
		t.Errorf("expected non-zero IssuedAt")
	}
	if out.Payload["k"] != "v" {
		t.Errorf("payload not preserved: %+v", out.Payload)
	}
}

func startTestGRPCServer(t *testing.T) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reg := NewRegistry(nil)
	srv := &GRPCServer{Registry: reg}
	gs := grpc.NewServer()
	pb.RegisterControlPlaneServer(gs, srv)
	go func() {
		_ = gs.Serve(lis)
	}()
	return lis.Addr().String(), func() {
		gs.Stop()
		_ = lis.Close()
	}
}

func TestRunOnceConnectAndDispatch(t *testing.T) {
	addr, stop := startTestGRPCServer(t)
	defer stop()

	dispatched := make(chan struct{}, 1)
	dispatcher := dispatcherFunc(func(ctx context.Context, cmd Command) CommandAck {
		select {
		case dispatched <- struct{}{}:
		default:
		}
		return CommandAck{ID: cmd.ID, Success: true}
	})

	c := NewGRPCClient(GRPCClientConfig{
		Endpoint:    addr,
		Identity:    AgentIdentity{InstanceID: "test-agent"},
		DialTimeout: 2 * time.Second,
		Dispatcher:  dispatcher,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErrCh := make(chan error, 1)
	go func() { runErrCh <- c.Run(ctx) }()

	deadline := time.After(3 * time.Second)
	for {
		c.mu.Lock()
		ready := c.stream != nil
		c.mu.Unlock()
		if ready {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("client never connected")
		case <-time.After(20 * time.Millisecond):
		}
	}

	if err := c.SendSnapshot(AgentSnapshot{Agent: AgentIdentity{InstanceID: "test-agent"}}); err != nil {
		t.Errorf("SendSnapshot: %v", err)
	}
	if err := c.SendAudit(map[string]any{"k": "v"}); err != nil {
		t.Errorf("SendAudit: %v", err)
	}
	if err := c.SendHeartbeat(); err != nil {
		t.Errorf("SendHeartbeat: %v", err)
	}

	cancel()
	select {
	case err := <-runErrCh:
		if err != nil {
			t.Errorf("Run returned %v, want nil after cancel", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Run did not return after cancel")
	}
	_ = dispatched
}

func TestRunOnceDialFails(t *testing.T) {
	c := NewGRPCClient(GRPCClientConfig{
		Endpoint:    "127.0.0.1:1",
		DialTimeout: 50 * time.Millisecond,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := c.runOnce(ctx)
	if err == nil {
		t.Errorf("expected dial error, got nil")
	}
}

func TestRunRetriesAfterFailure(t *testing.T) {
	c := NewGRPCClient(GRPCClientConfig{
		Endpoint:    "127.0.0.1:1",
		DialTimeout: 30 * time.Millisecond,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	err := c.Run(ctx)
	if err != nil {
		t.Errorf("Run returned %v after timeout, want nil", err)
	}
}

func TestRunOnceServerStopsMidStream(t *testing.T) {
	addr, stop := startTestGRPCServer(t)

	c := NewGRPCClient(GRPCClientConfig{
		Endpoint:    addr,
		Identity:    AgentIdentity{InstanceID: "kill-agent"},
		DialTimeout: 2 * time.Second,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	errCh := make(chan error, 1)
	go func() { errCh <- c.runOnce(context.Background()) }()

	deadline := time.After(3 * time.Second)
	for {
		c.mu.Lock()
		ready := c.stream != nil
		c.mu.Unlock()
		if ready {
			break
		}
		select {
		case <-deadline:
			stop()
			t.Fatalf("client never connected")
		case <-time.After(20 * time.Millisecond):
		}
	}

	stop()

	select {
	case err := <-errCh:
		if err == nil {
			t.Errorf("expected non-nil err when server stops mid-stream")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("runOnce did not return after server stopped")
	}
}

type dispatcherFunc func(ctx context.Context, cmd Command) CommandAck

func (f dispatcherFunc) Dispatch(ctx context.Context, cmd Command) CommandAck {
	return f(ctx, cmd)
}

func TestSendAuditInvalidPayload(t *testing.T) {
	addr, stop := startTestGRPCServer(t)
	defer stop()

	c := NewGRPCClient(GRPCClientConfig{
		Endpoint:    addr,
		Identity:    AgentIdentity{InstanceID: "audit-bad"},
		DialTimeout: 2 * time.Second,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	deadline := time.After(3 * time.Second)
	for {
		c.mu.Lock()
		ready := c.stream != nil
		c.mu.Unlock()
		if ready {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("client never connected")
		case <-time.After(20 * time.Millisecond):
		}
	}

	err := c.SendAudit(map[string]any{"bad": make(chan int)})
	if err == nil {
		t.Errorf("expected error for invalid payload")
	}
}

func TestSendSnapshotFillsDefaults(t *testing.T) {
	addr, stop := startTestGRPCServer(t)
	defer stop()

	id := AgentIdentity{InstanceID: "snap-defaults"}
	c := NewGRPCClient(GRPCClientConfig{
		Endpoint:    addr,
		Identity:    id,
		DialTimeout: 2 * time.Second,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	deadline := time.After(3 * time.Second)
	for {
		c.mu.Lock()
		ready := c.stream != nil
		c.mu.Unlock()
		if ready {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("client never connected")
		case <-time.After(20 * time.Millisecond):
		}
	}

	if err := c.SendSnapshot(AgentSnapshot{}); err != nil {
		t.Errorf("SendSnapshot: %v", err)
	}
}

func TestSendLog_StreamDown(t *testing.T) {
	c := NewGRPCClient(GRPCClientConfig{})
	if err := c.SendLog(LogLine{Line: "x"}); !errors.Is(err, ErrStreamDown) {
		t.Fatalf("got %v want ErrStreamDown", err)
	}
}

func TestSendLog_StreamConnected(t *testing.T) {
	addr, stop := startTestGRPCServer(t)
	defer stop()

	id := AgentIdentity{InstanceID: "log-test"}
	c := NewGRPCClient(GRPCClientConfig{
		Endpoint:    addr,
		Identity:    id,
		DialTimeout: 2 * time.Second,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	deadline := time.After(3 * time.Second)
	for {
		c.mu.Lock()
		ready := c.stream != nil
		c.mu.Unlock()
		if ready {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("client never connected")
		case <-time.After(20 * time.Millisecond):
		}
	}

	if err := c.SendLog(LogLine{Level: "info", Source: "audit", Line: "applied", Fields: map[string]string{"k": "v"}}); err != nil {
		t.Errorf("SendLog: %v", err)
	}
	if err := c.SendLog(LogLine{Line: "no-fields"}); err != nil {
		t.Errorf("SendLog (minimal): %v", err)
	}
}

func TestSendSnapshot_PreservesHostRulesLabel(t *testing.T) {
	store := NewMemoryStore()
	reg := NewRegistryWithStore(slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	srv := &GRPCServer{Registry: reg}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	pb.RegisterControlPlaneServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()
	defer lis.Close()

	baseID := AgentIdentity{InstanceID: "label-test"}
	c := NewGRPCClient(GRPCClientConfig{
		Endpoint:    lis.Addr().String(),
		Identity:    baseID,
		DialTimeout: 2 * time.Second,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	deadline := time.After(3 * time.Second)
	for {
		c.mu.Lock()
		ready := c.stream != nil
		c.mu.Unlock()
		if ready {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("client never connected")
		case <-time.After(20 * time.Millisecond):
		}
	}

	hostRulesJSON := `{"default":"DROP","rules":[{"name":"ssh","protocol":"tcp","ports":[22]}]}`
	snap := AgentSnapshot{
		Agent: AgentIdentity{
			InstanceID: "wrong-id",
			Hostname:   "wrong-host",
			Labels:     map[string]string{HostRulesLabelKey: hostRulesJSON},
		},
	}
	if err := c.SendSnapshot(snap); err != nil {
		t.Fatalf("SendSnapshot: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	persistedSnap, err := store.LatestSnapshot(context.Background(), "label-test")
	if err != nil {
		t.Fatalf("LatestSnapshot: %v", err)
	}
	if persistedSnap == nil {
		t.Fatal("expected snapshot to be persisted")
	}
	if persistedSnap.Agent.Labels[HostRulesLabelKey] != hostRulesJSON {
		t.Errorf("host_rules label not preserved: got %q, want %q", persistedSnap.Agent.Labels[HostRulesLabelKey], hostRulesJSON)
	}
	if persistedSnap.Agent.InstanceID != "label-test" {
		t.Errorf("instance ID not from config: got %q, want %q", persistedSnap.Agent.InstanceID, "label-test")
	}
}
