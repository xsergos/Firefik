package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPublishTemplate_InsertsAndBumpsVersion(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first, err := s.PublishTemplate(ctx, PolicyTemplate{
		Name:      "deny-egress",
		Body:      "default: deny",
		Labels:    map[string]string{"env": "prod"},
		Publisher: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != 1 {
		t.Errorf("first version = %d, want 1", first.Version)
	}
	if first.Publisher != "alice" {
		t.Errorf("publisher = %q", first.Publisher)
	}
	if first.Labels["env"] != "prod" {
		t.Errorf("labels = %v", first.Labels)
	}

	second, err := s.PublishTemplate(ctx, PolicyTemplate{
		Name: "deny-egress",
		Body: "default: deny\nrules: []",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Version != 2 {
		t.Errorf("second version = %d, want 2", second.Version)
	}
}

func TestPublishTemplate_RequiresName(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.PublishTemplate(context.Background(), PolicyTemplate{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestGetTemplate_NotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetTemplate(context.Background(), "absent"); !errors.Is(err, ErrTemplateNotFound) {
		t.Fatalf("expected ErrTemplateNotFound, got %v", err)
	}
}

func TestListTemplates_OrderedByName(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, name := range []string{"zeta", "alpha", "beta"} {
		if _, err := s.PublishTemplate(ctx, PolicyTemplate{Name: name, Body: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListTemplates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("len = %d", len(list))
	}
	if list[0].Name != "alpha" || list[1].Name != "beta" || list[2].Name != "zeta" {
		t.Errorf("order: %s, %s, %s", list[0].Name, list[1].Name, list[2].Name)
	}
}

func TestApprovalLifecycle_Approve(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	p, err := s.CreateApproval(ctx, PendingApproval{
		PolicyName:      "p",
		ProposedBody:    "body",
		Requester:       "alice",
		RequesterFinger: "fp-alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != ApprovalPending {
		t.Fatalf("status = %s", p.Status)
	}
	if p.ID == "" {
		t.Fatal("expected generated id")
	}

	approved, err := s.ApproveApproval(ctx, p.ID, "bob", "fp-bob")
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != ApprovalApproved {
		t.Errorf("status = %s", approved.Status)
	}
	if approved.Approver != "bob" {
		t.Errorf("approver = %s", approved.Approver)
	}
	if approved.ApprovedAt == nil {
		t.Error("approved_at not set")
	}
}

func TestApprovalLifecycle_Reject(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	p, err := s.CreateApproval(ctx, PendingApproval{
		PolicyName:      "p",
		ProposedBody:    "body",
		Requester:       "alice",
		RequesterFinger: "fp-alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := s.RejectApproval(ctx, p.ID, "bob", "fp-bob", "too restrictive")
	if err != nil {
		t.Fatal(err)
	}
	if rejected.Status != ApprovalRejected {
		t.Errorf("status = %s", rejected.Status)
	}
	if rejected.RejectionComment != "too restrictive" {
		t.Errorf("comment = %q", rejected.RejectionComment)
	}
}

func TestApprovalLifecycle_RejectsSelfApprove(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	p, _ := s.CreateApproval(ctx, PendingApproval{
		PolicyName:      "p",
		ProposedBody:    "body",
		Requester:       "alice",
		RequesterFinger: "fp-alice",
	})
	if _, err := s.ApproveApproval(ctx, p.ID, "alice", "fp-alice"); !errors.Is(err, ErrSelfApprove) {
		t.Fatalf("approve self-approve: got %v", err)
	}
	if _, err := s.RejectApproval(ctx, p.ID, "alice", "fp-alice", ""); !errors.Is(err, ErrSelfApprove) {
		t.Fatalf("reject self-approve: got %v", err)
	}
}

func TestApprovalLifecycle_NotPending(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	p, _ := s.CreateApproval(ctx, PendingApproval{
		PolicyName:      "p",
		ProposedBody:    "body",
		Requester:       "alice",
		RequesterFinger: "fp-alice",
	})
	if _, err := s.ApproveApproval(ctx, p.ID, "bob", "fp-bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveApproval(ctx, p.ID, "carol", "fp-carol"); !errors.Is(err, ErrApprovalNotPending) {
		t.Fatalf("expected ErrApprovalNotPending, got %v", err)
	}
}

func TestApprovalLifecycle_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.GetApproval(ctx, "missing"); !errors.Is(err, ErrApprovalNotFound) {
		t.Fatalf("got %v", err)
	}
	if _, err := s.ApproveApproval(ctx, "missing", "bob", "fp-bob"); !errors.Is(err, ErrApprovalNotFound) {
		t.Fatalf("got %v", err)
	}
	if _, err := s.RejectApproval(ctx, "missing", "bob", "fp-bob", ""); !errors.Is(err, ErrApprovalNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestListApprovals_FilterByStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateApproval(ctx, PendingApproval{
		PolicyName: "a", ProposedBody: "x", Requester: "alice", RequesterFinger: "fp-alice",
	})
	time.Sleep(2 * time.Millisecond)
	b, _ := s.CreateApproval(ctx, PendingApproval{
		PolicyName: "b", ProposedBody: "y", Requester: "alice", RequesterFinger: "fp-alice",
	})
	if _, err := s.ApproveApproval(ctx, a.ID, "bob", "fp-bob"); err != nil {
		t.Fatal(err)
	}
	pending, err := s.ListApprovals(ctx, ApprovalPending)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].ID != b.ID {
		t.Errorf("pending = %+v", pending)
	}
	approved, _ := s.ListApprovals(ctx, ApprovalApproved)
	if len(approved) != 1 || approved[0].ID != a.ID {
		t.Errorf("approved = %+v", approved)
	}
	all, _ := s.ListApprovals(ctx, "")
	if len(all) != 2 {
		t.Errorf("all = %d", len(all))
	}
}

func TestNewApprovalID_Stable(t *testing.T) {
	id1 := newApprovalID("p", "b", "f")
	id2 := newApprovalID("p", "b", "f")
	if id1 == id2 {
		t.Error("expected timestamp to vary id")
	}
	if len(id1) != 32 {
		t.Errorf("length = %d", len(id1))
	}
}

func TestMemStore_Templates(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	first, err := s.PublishTemplate(ctx, PolicyTemplate{Name: "x", Body: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != 1 {
		t.Errorf("version = %d", first.Version)
	}
	second, err := s.PublishTemplate(ctx, PolicyTemplate{Name: "x", Body: "b2"})
	if err != nil {
		t.Fatal(err)
	}
	if second.Version != 2 {
		t.Errorf("version = %d", second.Version)
	}
	if got, _ := s.GetTemplate(ctx, "x"); got.Body != "b2" {
		t.Errorf("body = %q", got.Body)
	}
	if _, err := s.GetTemplate(ctx, "absent"); !errors.Is(err, ErrTemplateNotFound) {
		t.Fatal(err)
	}
}

func TestMemStore_Approvals(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	p, err := s.CreateApproval(ctx, PendingApproval{
		PolicyName: "p", ProposedBody: "b", Requester: "alice", RequesterFinger: "fp-alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveApproval(ctx, p.ID, "alice", "fp-alice"); !errors.Is(err, ErrSelfApprove) {
		t.Fatal(err)
	}
	a, err := s.ApproveApproval(ctx, p.ID, "bob", "fp-bob")
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != ApprovalApproved {
		t.Errorf("status = %s", a.Status)
	}
}
