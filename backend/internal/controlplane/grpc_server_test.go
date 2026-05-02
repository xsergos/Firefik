package controlplane

import (
	"context"
	"io"
	"log/slog"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	pb "firefik/internal/controlplane/gen/controlplanev1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type testHarness struct {
	t        *testing.T
	registry *Registry
	server   *GRPCServer
	conn     *grpc.ClientConn
	stub     pb.ControlPlaneClient
	lis      net.Listener
	grpc     *grpc.Server
}

func newTestHarness(t *testing.T) *testHarness {
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

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		gs.Stop()
		t.Fatal(err)
	}
	return &testHarness{
		t:        t,
		registry: reg,
		server:   srv,
		conn:     conn,
		stub:     pb.NewControlPlaneClient(conn),
		lis:      lis,
		grpc:     gs,
	}
}

func (h *testHarness) close() {
	_ = h.conn.Close()
	h.grpc.GracefulStop()
}

func TestGRPCRegister(t *testing.T) {
	h := newTestHarness(t)
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ack, err := h.stub.Register(ctx, &pb.RegisterRequest{
		Identity: &pb.AgentIdentity{InstanceId: "agent-1", Hostname: "host-a"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if ack.ServerTime == nil {
		t.Fatalf("server_time missing")
	}
	if ack.HeartbeatIntervalSeconds != int64(DefaultHeartbeatInterval.Seconds()) {
		t.Fatalf("unexpected heartbeat: %d", ack.HeartbeatIntervalSeconds)
	}
	agents := h.registry.Agents()
	if len(agents) != 1 || agents[0].Identity.InstanceID != "agent-1" {
		t.Fatalf("registry state: %+v", agents)
	}
}

func TestGRPCRegisterRejectsMissingID(t *testing.T) {
	h := newTestHarness(t)
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := h.stub.Register(ctx, &pb.RegisterRequest{Identity: &pb.AgentIdentity{}})
	if err == nil {
		t.Fatalf("expected error for empty instance_id")
	}
}

func TestGRPCStreamSnapshotThenCommandPush(t *testing.T) {
	h := newTestHarness(t)
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := h.stub.Stream(ctx)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}

	err = stream.Send(&pb.AgentEvent{
		Kind: &pb.AgentEvent_Snapshot{Snapshot: &pb.AgentSnapshot{
			Agent: &pb.AgentIdentity{InstanceId: "agent-stream"},
			Containers: []*pb.ContainerState{
				{Id: "abc", Name: "demo", Status: "running", FirewallStatus: "active", RuleSetCount: 2},
			},
		}},
	})
	if err != nil {
		t.Fatalf("send snapshot: %v", err)
	}

	deadline := time.After(2 * time.Second)
	for {
		if len(h.registry.Agents()) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("server never saw snapshot")
		case <-time.After(20 * time.Millisecond):
		}
	}
	h.registry.Enqueue("agent-stream", Command{
		ID:          "cmd-1",
		Kind:        CommandApply,
		ContainerID: "abc",
		IssuedAt:    time.Now().UTC(),
	})

	cmd, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if cmd.Id != "cmd-1" || cmd.Kind != pb.CommandKind_COMMAND_KIND_APPLY || cmd.ContainerId != "abc" {
		t.Fatalf("unexpected command: %+v", cmd)
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}

	for {
		_, err := stream.Recv()
		if err != nil {
			break
		}
	}
	_ = io.EOF
}

func TestGRPCStreamFirstEventWithoutIdentityIsRejected(t *testing.T) {
	h := newTestHarness(t)
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := h.stub.Stream(ctx)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}

	if err := stream.Send(&pb.AgentEvent{
		Kind: &pb.AgentEvent_Heartbeat{Heartbeat: &pb.Heartbeat{}},
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if _, err := stream.Recv(); err == nil {
		t.Fatalf("expected InvalidArgument on first-event-without-id")
	}
}

func TestGRPCAck(t *testing.T) {
	h := newTestHarness(t)
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := h.stub.Ack(ctx, &pb.CommandAck{Id: "cmd-x", AgentId: "agent-1", Success: true})
	if err != nil {
		t.Fatalf("ack: %v", err)
	}
	h.registry.mu.RLock()
	got, ok := h.registry.acks["cmd-x"]
	h.registry.mu.RUnlock()
	if !ok || got.AgentID != "agent-1" || !got.Success {
		t.Fatalf("ack not recorded: %+v", got)
	}
}

func TestGRPCBearerInterceptorAccepts(t *testing.T) {

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reg := NewRegistry(nil)
	srv := &GRPCServer{Registry: reg}
	gs := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			if len(md.Get("authorization")) == 0 || md.Get("authorization")[0] != "Bearer secret" {
				return nil, grpcErrUnauthenticated()
			}
			return handler(ctx, req)
		}),
	)
	pb.RegisterControlPlaneServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	defer gs.GracefulStop()

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cli := pb.NewControlPlaneClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = cli.Register(ctx, &pb.RegisterRequest{Identity: &pb.AgentIdentity{InstanceId: "a"}})
	if err == nil {
		t.Fatalf("expected unauthenticated")
	}

	ctxOK := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer secret")
	_, err = cli.Register(ctxOK, &pb.RegisterRequest{Identity: &pb.AgentIdentity{InstanceId: "a"}})
	if err != nil {
		t.Fatalf("with token: %v", err)
	}
}

func grpcErrUnauthenticated() error {

	return context.Canceled
}

func TestAuthoriseEmptyTokenBypass(t *testing.T) {
	s := &GRPCServer{}
	if err := s.authorise(context.Background()); err != nil {
		t.Fatalf("empty token should bypass auth, got %v", err)
	}
}

func TestWithBearerStoresInContext(t *testing.T) {
	ctx := WithBearer(context.Background(), "abc")
	got, ok := ctx.Value(ctxBearerKey{}).(string)
	if !ok || got != "abc" {
		t.Errorf("got %q ok=%v", got, ok)
	}
}

func TestAuthoriseValidTokenInContext(t *testing.T) {
	s := &GRPCServer{Token: "secret"}
	ctx := context.WithValue(context.Background(), ctxBearerKey{}, "secret")
	if err := s.authorise(ctx); err != nil {
		t.Fatalf("valid token should pass, got %v", err)
	}
}

func TestAuthoriseMissingTokenValueUnauthenticated(t *testing.T) {
	s := &GRPCServer{Token: "secret"}
	err := s.authorise(context.Background())
	if err == nil {
		t.Fatalf("expected Unauthenticated error, got nil")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated code, got %v", err)
	}
}

func TestAuthoriseWrongTokenUnauthenticated(t *testing.T) {
	s := &GRPCServer{Token: "secret"}
	ctx := context.WithValue(context.Background(), ctxBearerKey{}, "nope")
	err := s.authorise(ctx)
	if err == nil {
		t.Fatalf("expected Unauthenticated error for wrong token")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestAuthoriseWrongTypeInContextUnauthenticated(t *testing.T) {
	s := &GRPCServer{Token: "secret"}
	ctx := context.WithValue(context.Background(), ctxBearerKey{}, 42)
	if err := s.authorise(ctx); err == nil {
		t.Fatalf("expected Unauthenticated for wrong-type value")
	}
}

func TestPbKindFromStringAllBranches(t *testing.T) {
	cases := []struct {
		in   string
		want pb.CommandKind
	}{
		{string(CommandApply), pb.CommandKind_COMMAND_KIND_APPLY},
		{string(CommandDisable), pb.CommandKind_COMMAND_KIND_DISABLE},
		{string(CommandReconcile), pb.CommandKind_COMMAND_KIND_RECONCILE},
		{string(CommandTokenRotate), pb.CommandKind_COMMAND_KIND_TOKEN_ROTATE},
		{"", pb.CommandKind_COMMAND_KIND_UNSPECIFIED},
		{"totally-unknown", pb.CommandKind_COMMAND_KIND_UNSPECIFIED},
	}
	for _, c := range cases {
		if got := pbKindFromString(c.in); got != c.want {
			t.Fatalf("pbKindFromString(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCopyLabelsNil(t *testing.T) {
	if got := copyLabels(nil); got != nil {
		t.Fatalf("nil input should yield nil, got %v", got)
	}
}

func TestCopyLabelsEmpty(t *testing.T) {
	if got := copyLabels(map[string]string{}); got != nil {
		t.Fatalf("empty input should yield nil, got %v", got)
	}
}

func TestCopyLabelsDeepCopy(t *testing.T) {
	src := map[string]string{"env": "prod", "tier": "edge"}
	got := copyLabels(src)
	if !reflect.DeepEqual(got, src) {
		t.Fatalf("copyLabels mismatch: got %v want %v", got, src)
	}
	got["env"] = "mutated"
	if src["env"] != "prod" {
		t.Fatalf("mutation of copy affected source: %v", src)
	}
}

func TestHandleEventNilEvent(t *testing.T) {
	reg := NewRegistry(nil)
	s := &GRPCServer{Registry: reg}
	s.handleEvent(nil)
	if len(reg.Agents()) != 0 {
		t.Fatalf("nil event should be a no-op")
	}
}

func TestHandleEventSnapshotStored(t *testing.T) {
	reg := NewRegistry(nil)
	s := &GRPCServer{Registry: reg}
	ev := &pb.AgentEvent{
		Kind: &pb.AgentEvent_Snapshot{Snapshot: &pb.AgentSnapshot{
			Agent: &pb.AgentIdentity{InstanceId: "a-1", Hostname: "h"},
			At:    timestamppb.Now(),
			Containers: []*pb.ContainerState{
				{Id: "c1", Name: "n1", Status: "running", Labels: map[string]string{"k": "v"}},
			},
		}},
	}
	s.handleEvent(ev)
	agents := reg.Agents()
	if len(agents) != 1 || agents[0].Identity.InstanceID != "a-1" {
		t.Fatalf("agent not registered: %+v", agents)
	}
	reg.mu.RLock()
	entry := reg.agents["a-1"]
	snap := entry.Snapshot
	reg.mu.RUnlock()
	if snap == nil || len(snap.Containers) != 1 || snap.Containers[0].ID != "c1" {
		t.Fatalf("snapshot not attached to entry: %+v", snap)
	}
}

func TestHandleEventSnapshotNilInnerIgnored(t *testing.T) {
	reg := NewRegistry(nil)
	s := &GRPCServer{Registry: reg}
	s.handleEvent(&pb.AgentEvent{Kind: &pb.AgentEvent_Snapshot{Snapshot: nil}})
	if len(reg.Agents()) != 0 {
		t.Fatalf("snapshot with nil inner should not register an agent")
	}
	s.handleEvent(&pb.AgentEvent{Kind: &pb.AgentEvent_Snapshot{Snapshot: &pb.AgentSnapshot{Agent: nil}}})
	if len(reg.Agents()) != 0 {
		t.Fatalf("snapshot without agent should not register")
	}
}

func TestHandleEventAuditIncrementsCounter(t *testing.T) {
	reg := NewRegistry(nil)
	s := &GRPCServer{Registry: reg}
	ev := &pb.AgentEvent{
		Kind: &pb.AgentEvent_Audit{Audit: &pb.AuditEvent{
			Agent: &pb.AgentIdentity{InstanceId: "audit-agent"},
			Event: &structpb.Struct{},
		}},
	}
	s.handleEvent(ev)
	s.handleEvent(ev)
	reg.mu.RLock()
	entry := reg.agents["audit-agent"]
	events := 0
	if entry != nil {
		events = entry.Events
	}
	reg.mu.RUnlock()
	if events != 2 {
		t.Fatalf("expected Events=2 after two audit events, got %d", events)
	}
}

func TestHandleEventAuditNilIgnored(t *testing.T) {
	reg := NewRegistry(nil)
	s := &GRPCServer{Registry: reg}
	s.handleEvent(&pb.AgentEvent{Kind: &pb.AgentEvent_Audit{Audit: nil}})
	s.handleEvent(&pb.AgentEvent{Kind: &pb.AgentEvent_Audit{Audit: &pb.AuditEvent{Agent: nil}}})
	if len(reg.Agents()) != 0 {
		t.Fatalf("audit with nil inner/agent should not register")
	}
}

func TestHandleEventHeartbeat(t *testing.T) {
	reg := NewRegistry(nil)
	s := &GRPCServer{Registry: reg}
	s.handleEvent(&pb.AgentEvent{Kind: &pb.AgentEvent_Heartbeat{Heartbeat: &pb.Heartbeat{
		Agent: &pb.AgentIdentity{InstanceId: "hb-agent"},
	}}})
	agents := reg.Agents()
	if len(agents) != 1 || agents[0].Identity.InstanceID != "hb-agent" {
		t.Fatalf("heartbeat should upsert agent: %+v", agents)
	}
}

func TestHandleEventHeartbeatNilIgnored(t *testing.T) {
	reg := NewRegistry(nil)
	s := &GRPCServer{Registry: reg}
	s.handleEvent(&pb.AgentEvent{Kind: &pb.AgentEvent_Heartbeat{Heartbeat: nil}})
	s.handleEvent(&pb.AgentEvent{Kind: &pb.AgentEvent_Heartbeat{Heartbeat: &pb.Heartbeat{Agent: nil}}})
	if len(reg.Agents()) != 0 {
		t.Fatalf("heartbeat with nil inner/agent should not register")
	}
}

func TestHandleEventUnknownKindIgnored(t *testing.T) {
	reg := NewRegistry(nil)
	s := &GRPCServer{Registry: reg}
	s.handleEvent(&pb.AgentEvent{})
	if len(reg.Agents()) != 0 {
		t.Fatalf("event with unset Kind should be a no-op")
	}
}

func TestAgentIDFromEventAllBranches(t *testing.T) {
	if _, ok := agentIDFromEvent(&pb.AgentEvent{}); ok {
		t.Fatalf("empty event should not yield id")
	}
	if id, ok := agentIDFromEvent(&pb.AgentEvent{
		Kind: &pb.AgentEvent_Snapshot{Snapshot: &pb.AgentSnapshot{Agent: &pb.AgentIdentity{InstanceId: "s1"}}},
	}); !ok || id != "s1" {
		t.Fatalf("snapshot: got %q ok=%v", id, ok)
	}
	if _, ok := agentIDFromEvent(&pb.AgentEvent{
		Kind: &pb.AgentEvent_Snapshot{Snapshot: &pb.AgentSnapshot{Agent: &pb.AgentIdentity{InstanceId: ""}}},
	}); ok {
		t.Fatalf("snapshot with empty id should not be ok")
	}
	if id, ok := agentIDFromEvent(&pb.AgentEvent{
		Kind: &pb.AgentEvent_Audit{Audit: &pb.AuditEvent{Agent: &pb.AgentIdentity{InstanceId: "a1"}}},
	}); !ok || id != "a1" {
		t.Fatalf("audit: got %q ok=%v", id, ok)
	}
	if id, ok := agentIDFromEvent(&pb.AgentEvent{
		Kind: &pb.AgentEvent_Heartbeat{Heartbeat: &pb.Heartbeat{Agent: &pb.AgentIdentity{InstanceId: "h1"}}},
	}); !ok || id != "h1" {
		t.Fatalf("heartbeat: got %q ok=%v", id, ok)
	}
	if _, ok := agentIDFromEvent(&pb.AgentEvent{
		Kind: &pb.AgentEvent_Snapshot{Snapshot: &pb.AgentSnapshot{Agent: nil}},
	}); ok {
		t.Fatalf("snapshot with nil agent should not be ok")
	}
}

func TestToNativeIdentityNil(t *testing.T) {
	if got := toNativeIdentity(nil); got.InstanceID != "" || got.Labels != nil {
		t.Fatalf("nil input should yield zero value, got %+v", got)
	}
}

func TestToNativeAckAllFields(t *testing.T) {
	ts := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	out := toNativeAck(&pb.CommandAck{
		Id:          "id",
		AgentId:     "ag",
		Success:     true,
		Error:       "",
		CompletedAt: timestamppb.New(ts),
	})
	if out.ID != "id" || out.AgentID != "ag" || !out.Success || !out.CompletedAt.Equal(ts) {
		t.Fatalf("unexpected ack: %+v", out)
	}
}

func TestToPBCommandWithPayload(t *testing.T) {
	cmd := Command{
		ID:          "x",
		Kind:        CommandDisable,
		ContainerID: "c",
		IssuedAt:    time.Now().UTC(),
		Payload:     map[string]any{"reason": "rollout"},
	}
	got := toPBCommand(cmd)
	if got.Id != "x" || got.Kind != pb.CommandKind_COMMAND_KIND_DISABLE || got.ContainerId != "c" {
		t.Fatalf("unexpected: %+v", got)
	}
	if got.Payload == nil {
		t.Fatalf("payload should be set")
	}
	if v, ok := got.Payload.Fields["reason"]; !ok || v.GetStringValue() != "rollout" {
		t.Fatalf("payload reason missing: %+v", got.Payload.Fields)
	}
}

func TestToPBCommandInvalidPayloadDropped(t *testing.T) {
	cmd := Command{
		ID:       "x",
		Kind:     CommandReconcile,
		IssuedAt: time.Now().UTC(),
		Payload:  map[string]any{"bad": make(chan int)},
	}
	got := toPBCommand(cmd)
	if got.Payload != nil {
		t.Fatalf("invalid payload should be dropped, got %+v", got.Payload)
	}
}

func TestActiveStreamsCounter(t *testing.T) {
	s := &GRPCServer{Registry: NewRegistry(nil)}
	if n := s.ActiveStreams(); n != 0 {
		t.Fatalf("expected 0, got %d", n)
	}
	s.onConnect("a")
	if n := s.ActiveStreams(); n != 1 {
		t.Fatalf("expected 1 after connect, got %d", n)
	}
	s.onDisconnect("a")
	if n := s.ActiveStreams(); n != 0 {
		t.Fatalf("expected 0 after disconnect, got %d", n)
	}
}

func TestOnConnectOnDisconnectWithLogger(t *testing.T) {
	s := &GRPCServer{Registry: NewRegistry(nil), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.onConnect("logged-agent")
	s.onDisconnect("logged-agent")
	if n := s.ActiveStreams(); n != 0 {
		t.Fatalf("streams not balanced: %d", n)
	}
}

func TestStreamRejectsInvalidToken(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	reg := NewRegistry(nil)
	srv := &GRPCServer{Registry: reg, Token: "secret"}
	gs := grpc.NewServer(
		grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			md, _ := metadata.FromIncomingContext(ss.Context())
			toks := md.Get("authorization")
			var tok string
			if len(toks) > 0 {
				tok = toks[0]
			}
			wrapped := &wrappedStream{ServerStream: ss, ctx: context.WithValue(ss.Context(), ctxBearerKey{}, tok)}
			return handler(srv, wrapped)
		}),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			var tok string
			if toks := md.Get("authorization"); len(toks) > 0 {
				tok = toks[0]
			}
			return handler(context.WithValue(ctx, ctxBearerKey{}, tok), req)
		}),
	)
	pb.RegisterControlPlaneServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	defer gs.GracefulStop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cli := pb.NewControlPlaneClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := cli.Stream(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := stream.Send(&pb.AgentEvent{Kind: &pb.AgentEvent_Heartbeat{Heartbeat: &pb.Heartbeat{Agent: &pb.AgentIdentity{InstanceId: "x"}}}}); err != nil {
		t.Fatalf("send: %v", err)
	}
	_, err = stream.Recv()
	if err == nil {
		t.Fatalf("expected Unauthenticated, got nil")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated code, got %v", err)
	}

	authCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "secret")
	stream2, err := cli.Stream(authCtx)
	if err != nil {
		t.Fatalf("open authed stream: %v", err)
	}
	if err := stream2.Send(&pb.AgentEvent{Kind: &pb.AgentEvent_Heartbeat{Heartbeat: &pb.Heartbeat{Agent: &pb.AgentIdentity{InstanceId: "y"}}}}); err != nil {
		t.Fatalf("send2: %v", err)
	}
	if err := stream2.CloseSend(); err != nil {
		t.Fatalf("close: %v", err)
	}

	deadline := time.After(2 * time.Second)
	for {
		if len(reg.Agents()) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("authed stream never registered agent")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

func TestStreamClientCloseSendEndsCleanly(t *testing.T) {
	h := newTestHarness(t)
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := h.stub.Stream(ctx)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if err := stream.Send(&pb.AgentEvent{
		Kind: &pb.AgentEvent_Heartbeat{Heartbeat: &pb.Heartbeat{Agent: &pb.AgentIdentity{InstanceId: "close-clean"}}},
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}
	for {
		_, err := stream.Recv()
		if err == nil {
			continue
		}
		break
	}
}

func TestStreamContextCancelledReturnsNil(t *testing.T) {
	h := newTestHarness(t)
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := h.stub.Stream(ctx)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if err := stream.Send(&pb.AgentEvent{
		Kind: &pb.AgentEvent_Heartbeat{Heartbeat: &pb.Heartbeat{Agent: &pb.AgentIdentity{InstanceId: "cancel-me"}}},
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	deadline := time.After(2 * time.Second)
	for {
		if h.server.ActiveStreams() > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("stream never reported active")
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	deadline = time.After(2 * time.Second)
	for {
		if h.server.ActiveStreams() == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("stream did not disconnect after cancel")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestRegisterUnauthenticated(t *testing.T) {
	s := &GRPCServer{Registry: NewRegistry(nil), Token: "secret"}
	_, err := s.Register(context.Background(), &pb.RegisterRequest{Identity: &pb.AgentIdentity{InstanceId: "a"}})
	if err == nil {
		t.Fatalf("expected Unauthenticated")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestRegisterNilRequest(t *testing.T) {
	s := &GRPCServer{Registry: NewRegistry(nil)}
	_, err := s.Register(context.Background(), nil)
	if err == nil {
		t.Fatalf("expected InvalidArgument on nil req")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestRegisterReplacesSameAgent(t *testing.T) {
	s := &GRPCServer{Registry: NewRegistry(nil)}
	if _, err := s.Register(context.Background(), &pb.RegisterRequest{Identity: &pb.AgentIdentity{InstanceId: "dup", Hostname: "v1"}}); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := s.Register(context.Background(), &pb.RegisterRequest{Identity: &pb.AgentIdentity{InstanceId: "dup", Hostname: "v2"}}); err != nil {
		t.Fatalf("second: %v", err)
	}
	agents := s.Registry.Agents()
	if len(agents) != 1 {
		t.Fatalf("expected single agent, got %d", len(agents))
	}
	if agents[0].Identity.Hostname != "v2" {
		t.Fatalf("second register should replace first, got %+v", agents[0].Identity)
	}
}

func TestRegisterConcurrent(t *testing.T) {
	s := &GRPCServer{Registry: NewRegistry(nil)}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.Register(context.Background(), &pb.RegisterRequest{Identity: &pb.AgentIdentity{InstanceId: "race", Hostname: "h"}})
		}()
	}
	wg.Wait()
	if got := len(s.Registry.Agents()); got != 1 {
		t.Fatalf("concurrent registers should collapse to one entry, got %d", got)
	}
}

func TestAckUnauthenticated(t *testing.T) {
	s := &GRPCServer{Registry: NewRegistry(nil), Token: "secret"}
	_, err := s.Ack(context.Background(), &pb.CommandAck{Id: "x"})
	if err == nil {
		t.Fatalf("expected Unauthenticated")
	}
}

func TestAckMissingID(t *testing.T) {
	s := &GRPCServer{Registry: NewRegistry(nil)}
	_, err := s.Ack(context.Background(), &pb.CommandAck{Id: ""})
	if err == nil {
		t.Fatalf("expected InvalidArgument")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestAckNilRequest(t *testing.T) {
	s := &GRPCServer{Registry: NewRegistry(nil)}
	_, err := s.Ack(context.Background(), nil)
	if err == nil {
		t.Fatalf("expected InvalidArgument on nil ack")
	}
}
