package controlplane

import (
	"context"
	"errors"

	pb "firefik/internal/controlplane/gen/controlplanev1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *GRPCServer) ListTemplates(ctx context.Context, _ *pb.ListTemplatesRequest) (*pb.ListTemplatesResponse, error) {
	if err := s.authorise(ctx); err != nil {
		return nil, err
	}
	if s.Registry == nil || s.Registry.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "store unavailable")
	}
	list, err := s.Registry.store.ListTemplates(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := &pb.ListTemplatesResponse{Templates: make([]*pb.PolicyTemplate, 0, len(list))}
	for _, t := range list {
		out.Templates = append(out.Templates, toPBTemplate(t))
	}
	return out, nil
}

func (s *GRPCServer) GetTemplate(ctx context.Context, req *pb.GetTemplateRequest) (*pb.PolicyTemplate, error) {
	if err := s.authorise(ctx); err != nil {
		return nil, err
	}
	if req == nil || req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	if s.Registry == nil || s.Registry.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "store unavailable")
	}
	t, err := s.Registry.store.GetTemplate(ctx, req.Name)
	if err != nil {
		if errors.Is(err, ErrTemplateNotFound) {
			return nil, status.Error(codes.NotFound, "template not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return toPBTemplate(t), nil
}

func (s *GRPCServer) PublishTemplate(ctx context.Context, req *pb.PublishTemplateRequest) (*pb.PublishTemplateResponse, error) {
	if err := s.authorise(ctx); err != nil {
		return nil, err
	}
	if req == nil || req.Template == nil || req.Template.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "template.name required")
	}
	if s.Registry == nil || s.Registry.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "store unavailable")
	}
	t, err := s.Registry.store.PublishTemplate(ctx, fromPBTemplate(req.Template))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.PublishTemplateResponse{Template: toPBTemplate(t)}, nil
}

func toPBTemplate(t PolicyTemplate) *pb.PolicyTemplate {
	out := &pb.PolicyTemplate{
		Name:      t.Name,
		Version:   t.Version,
		Body:      t.Body,
		Labels:    copyLabels(t.Labels),
		Publisher: t.Publisher,
	}
	if !t.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(t.CreatedAt)
	}
	if !t.UpdatedAt.IsZero() {
		out.UpdatedAt = timestamppb.New(t.UpdatedAt)
	}
	return out
}

func fromPBTemplate(t *pb.PolicyTemplate) PolicyTemplate {
	if t == nil {
		return PolicyTemplate{}
	}
	out := PolicyTemplate{
		Name:      t.Name,
		Version:   t.Version,
		Body:      t.Body,
		Labels:    copyLabels(t.Labels),
		Publisher: t.Publisher,
	}
	if t.CreatedAt != nil {
		out.CreatedAt = t.CreatedAt.AsTime()
	}
	if t.UpdatedAt != nil {
		out.UpdatedAt = t.UpdatedAt.AsTime()
	}
	return out
}
