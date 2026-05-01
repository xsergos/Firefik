package controlplane

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	pb "firefik/internal/controlplane/gen/controlplanev1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const streamPollInterval = 50 * time.Millisecond

const DefaultHeartbeatInterval = 30 * time.Second

type GRPCServer struct {
	pb.UnimplementedControlPlaneServer

	Registry *Registry
	Token    string
	Logger   *slog.Logger

	activeStreams atomic.Int64
}

func (s *GRPCServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterAck, error) {
	if err := s.authorise(ctx); err != nil {
		return nil, err
	}
	if req == nil || req.Identity == nil || req.Identity.InstanceId == "" {
		return nil, status.Error(codes.InvalidArgument, "identity.instance_id required")
	}
	s.Registry.upsertAgent(toNativeIdentity(req.Identity))
	TransportMix.WithLabelValues("grpc").Inc()
	return &pb.RegisterAck{
		ServerTime:               timestamppb.Now(),
		HeartbeatIntervalSeconds: int64(DefaultHeartbeatInterval.Seconds()),
	}, nil
}

func (s *GRPCServer) Stream(stream pb.ControlPlane_StreamServer) error {
	if err := s.authorise(stream.Context()); err != nil {
		return err
	}

	first, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	id, ok := agentIDFromEvent(first)
	if !ok {
		return status.Error(codes.InvalidArgument, "first stream event must include agent.identity")
	}
	s.handleEvent(first)
	s.onConnect(id)
	defer s.onDisconnect(id)

	ctx := stream.Context()
	errCh := make(chan error, 2)

	go func() {
		for {
			ev, err := stream.Recv()
			if err != nil {
				errCh <- err
				return
			}
			s.handleEvent(ev)
		}
	}()

	go func() {
		t := time.NewTicker(streamPollInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case <-t.C:
				cmds := s.Registry.takeCommands(id)
				for _, cmd := range cmds {
					if err := stream.Send(toPBCommand(cmd)); err != nil {
						errCh <- err
						return
					}
				}
			}
		}
	}()

	err = <-errCh
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (s *GRPCServer) Ack(ctx context.Context, a *pb.CommandAck) (*pb.AckReply, error) {
	if err := s.authorise(ctx); err != nil {
		return nil, err
	}
	if a == nil || a.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	s.Registry.recordAck(toNativeAck(a))
	return &pb.AckReply{}, nil
}

func (s *GRPCServer) ActiveStreams() int64 { return s.activeStreams.Load() }

func (s *GRPCServer) onConnect(agentID string) {
	s.activeStreams.Add(1)
	grpcConnectedAgents.Inc()
	if s.Logger != nil {
		if p, ok := peer.FromContext(context.Background()); ok && p != nil {
			s.Logger.Debug("grpc stream opened", "agent_id", agentID, "peer", p.Addr.String())
		} else {
			s.Logger.Debug("grpc stream opened", "agent_id", agentID)
		}
	}
}

func (s *GRPCServer) onDisconnect(agentID string) {
	s.activeStreams.Add(-1)
	grpcConnectedAgents.Dec()
	if s.Logger != nil {
		s.Logger.Debug("grpc stream closed", "agent_id", agentID)
	}
}

func (s *GRPCServer) handleEvent(ev *pb.AgentEvent) {
	if ev == nil {
		return
	}
	switch k := ev.Kind.(type) {
	case *pb.AgentEvent_Snapshot:
		if k.Snapshot == nil || k.Snapshot.Agent == nil {
			return
		}
		snap := toNativeSnapshot(k.Snapshot)
		e := s.Registry.upsertAgent(snap.Agent)
		s.Registry.mu.Lock()
		e.Snapshot = &snap
		s.Registry.mu.Unlock()
	case *pb.AgentEvent_Audit:
		if k.Audit == nil || k.Audit.Agent == nil {
			return
		}
		e := s.Registry.upsertAgent(toNativeIdentity(k.Audit.Agent))
		s.Registry.mu.Lock()
		e.Events++
		s.Registry.mu.Unlock()
	case *pb.AgentEvent_Heartbeat:
		if k.Heartbeat == nil || k.Heartbeat.Agent == nil {
			return
		}
		s.Registry.upsertAgent(toNativeIdentity(k.Heartbeat.Agent))
	}
}

type ctxBearerKey struct{}

func WithBearer(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxBearerKey{}, token)
}

func (s *GRPCServer) authorise(ctx context.Context) error {
	if s.Token == "" {
		return nil
	}
	if tok, ok := ctx.Value(ctxBearerKey{}).(string); ok && tok == s.Token {
		return nil
	}

	return status.Error(codes.Unauthenticated, "missing or invalid bearer token")
}

func agentIDFromEvent(ev *pb.AgentEvent) (string, bool) {
	switch k := ev.GetKind().(type) {
	case *pb.AgentEvent_Snapshot:
		if k.Snapshot != nil && k.Snapshot.Agent != nil {
			return k.Snapshot.Agent.InstanceId, k.Snapshot.Agent.InstanceId != ""
		}
	case *pb.AgentEvent_Audit:
		if k.Audit != nil && k.Audit.Agent != nil {
			return k.Audit.Agent.InstanceId, k.Audit.Agent.InstanceId != ""
		}
	case *pb.AgentEvent_Heartbeat:
		if k.Heartbeat != nil && k.Heartbeat.Agent != nil {
			return k.Heartbeat.Agent.InstanceId, k.Heartbeat.Agent.InstanceId != ""
		}
	}
	return "", false
}

func toNativeIdentity(in *pb.AgentIdentity) AgentIdentity {
	if in == nil {
		return AgentIdentity{}
	}
	return AgentIdentity{
		InstanceID: in.InstanceId,
		Hostname:   in.Hostname,
		Version:    in.Version,
		Backend:    in.Backend,
		Chain:      in.Chain,
		Labels:     copyLabels(in.Labels),
	}
}

func toNativeSnapshot(in *pb.AgentSnapshot) AgentSnapshot {
	out := AgentSnapshot{Agent: toNativeIdentity(in.Agent)}
	if in.At != nil {
		out.At = in.At.AsTime()
	}
	for _, c := range in.Containers {
		out.Containers = append(out.Containers, ContainerState{
			ID:             c.Id,
			Name:           c.Name,
			Status:         c.Status,
			FirewallStatus: c.FirewallStatus,
			DefaultPolicy:  c.DefaultPolicy,
			Labels:         copyLabels(c.Labels),
			RuleSetCount:   int(c.RuleSetCount),
		})
	}
	return out
}

func toNativeAck(in *pb.CommandAck) CommandAck {
	out := CommandAck{
		ID:      in.Id,
		AgentID: in.AgentId,
		Success: in.Success,
		Error:   in.Error,
	}
	if in.CompletedAt != nil {
		out.CompletedAt = in.CompletedAt.AsTime()
	}
	return out
}

func toPBCommand(c Command) *pb.ServerCommand {
	out := &pb.ServerCommand{
		Id:          c.ID,
		Kind:        pbKindFromString(string(c.Kind)),
		ContainerId: c.ContainerID,
		IssuedAt:    timestamppb.New(c.IssuedAt),
	}
	if len(c.Payload) > 0 {
		if p, err := structpb.NewStruct(c.Payload); err == nil {
			out.Payload = p
		}
	}
	return out
}

func pbKindFromString(s string) pb.CommandKind {
	switch s {
	case string(CommandApply):
		return pb.CommandKind_COMMAND_KIND_APPLY
	case string(CommandDisable):
		return pb.CommandKind_COMMAND_KIND_DISABLE
	case string(CommandReconcile):
		return pb.CommandKind_COMMAND_KIND_RECONCILE
	case string(CommandTokenRotate):
		return pb.CommandKind_COMMAND_KIND_TOKEN_ROTATE
	default:
		return pb.CommandKind_COMMAND_KIND_UNSPECIFIED
	}
}

func copyLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
