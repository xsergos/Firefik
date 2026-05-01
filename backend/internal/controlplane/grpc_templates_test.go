package controlplane

import (
	"context"
	"testing"
	"time"

	pb "firefik/internal/controlplane/gen/controlplanev1"
)

func TestGetTemplateNoAuth(t *testing.T) {
	s := &GRPCServer{Token: "x"}
	if _, err := s.GetTemplate(context.Background(), &pb.GetTemplateRequest{Name: "t"}); err == nil {
		t.Errorf("expected unauth")
	}
}

func TestGetTemplateMissingName(t *testing.T) {
	s := &GRPCServer{}
	if _, err := s.GetTemplate(context.Background(), &pb.GetTemplateRequest{}); err == nil {
		t.Errorf("expected error")
	}
	if _, err := s.GetTemplate(context.Background(), nil); err == nil {
		t.Errorf("expected error")
	}
}

func TestGetTemplateNoStore(t *testing.T) {
	s := &GRPCServer{Registry: NewRegistryWithStore(nil, nil)}
	if _, err := s.GetTemplate(context.Background(), &pb.GetTemplateRequest{Name: "t"}); err == nil {
		t.Errorf("expected error")
	}
}

func TestGetTemplateNotFound(t *testing.T) {
	store := newTestStore(t)
	s := &GRPCServer{Registry: NewRegistryWithStore(nil, store)}
	if _, err := s.GetTemplate(context.Background(), &pb.GetTemplateRequest{Name: "missing"}); err == nil {
		t.Errorf("expected not found")
	}
}

func TestGetTemplateSuccess(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.PublishTemplate(context.Background(), PolicyTemplate{Name: "t", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	s := &GRPCServer{Registry: NewRegistryWithStore(nil, store)}
	got, err := s.GetTemplate(context.Background(), &pb.GetTemplateRequest{Name: "t"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.Name != "t" {
		t.Errorf("got %+v", got)
	}
}

func TestPublishTemplateMissing(t *testing.T) {
	s := &GRPCServer{}
	if _, err := s.PublishTemplate(context.Background(), nil); err == nil {
		t.Errorf("expected error")
	}
	if _, err := s.PublishTemplate(context.Background(), &pb.PublishTemplateRequest{}); err == nil {
		t.Errorf("expected error")
	}
}

func TestPublishTemplateNoStore(t *testing.T) {
	s := &GRPCServer{Registry: NewRegistryWithStore(nil, nil)}
	if _, err := s.PublishTemplate(context.Background(), &pb.PublishTemplateRequest{Template: &pb.PolicyTemplate{Name: "t"}}); err == nil {
		t.Errorf("expected error")
	}
}

func TestPublishTemplateSuccess(t *testing.T) {
	store := newTestStore(t)
	s := &GRPCServer{Registry: NewRegistryWithStore(nil, store)}
	resp, err := s.PublishTemplate(context.Background(), &pb.PublishTemplateRequest{Template: &pb.PolicyTemplate{Name: "t", Body: "b"}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp.Template.Name != "t" {
		t.Errorf("got %+v", resp.Template)
	}
}

func TestToPBTemplate(t *testing.T) {
	now := time.Now()
	out := toPBTemplate(PolicyTemplate{Name: "t", Version: 2, Body: "b", CreatedAt: now, UpdatedAt: now})
	if out.Name != "t" || out.Version != 2 || out.CreatedAt == nil || out.UpdatedAt == nil {
		t.Errorf("got %+v", out)
	}
}

func TestFromPBTemplateNil(t *testing.T) {
	if got := fromPBTemplate(nil); got.Name != "" {
		t.Errorf("nil should yield zero")
	}
}

func TestFromPBTemplateBasic(t *testing.T) {
	out := fromPBTemplate(&pb.PolicyTemplate{Name: "t", Version: 3})
	if out.Name != "t" || out.Version != 3 {
		t.Errorf("got %+v", out)
	}
}
