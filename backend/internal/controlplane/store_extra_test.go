package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemStoreUpsertAndList(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	if err := s.UpsertAgent(ctx, AgentIdentity{InstanceID: "a1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAgent(ctx, AgentIdentity{InstanceID: "a2"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAgent(ctx, AgentIdentity{InstanceID: "a1", Hostname: "updated"}); err != nil {
		t.Fatal(err)
	}
	recs, err := s.ListAgents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Errorf("len = %d", len(recs))
	}
}

func TestMemStoreRecordSnapshot(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	if err := s.RecordSnapshot(ctx, AgentSnapshot{Agent: AgentIdentity{InstanceID: "a1"}}); err != nil {
		t.Fatal(err)
	}
	recs, _ := s.ListAgents(ctx)
	if len(recs) != 1 || !recs[0].HasSnapshot {
		t.Errorf("HasSnapshot not set: %+v", recs)
	}
}

func TestMemStoreRecordAudit(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	_ = s.UpsertAgent(ctx, AgentIdentity{InstanceID: "a1"})
	if err := s.RecordAudit(ctx, "a1", "apply", map[string]any{"x": 1}, time.Now()); err != nil {
		t.Fatal(err)
	}
	recs, _ := s.ListAgents(ctx)
	if len(recs) != 1 || recs[0].EventCount != 1 {
		t.Errorf("EventCount = %d", recs[0].EventCount)
	}
}

func TestMemStoreEnqueueRequiresID(t *testing.T) {
	s := NewMemoryStore()
	if err := s.EnqueueCommand(context.Background(), "a", Command{}); err == nil {
		t.Errorf("expected error")
	}
}

func TestMemStoreTakeCommands(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	if err := s.EnqueueCommand(ctx, "a", Command{ID: "c1", Kind: CommandApply}); err != nil {
		t.Fatal(err)
	}
	cmds, _ := s.TakeCommands(ctx, "a")
	if len(cmds) != 1 || cmds[0].ID != "c1" {
		t.Errorf("got %+v", cmds)
	}
	cmds2, _ := s.TakeCommands(ctx, "a")
	if len(cmds2) != 0 {
		t.Errorf("second take should be empty")
	}
}

func TestMemStoreRecordAck(t *testing.T) {
	s := NewMemoryStore()
	if err := s.RecordAck(context.Background(), CommandAck{}); err == nil {
		t.Errorf("expected error on missing ID")
	}
	if err := s.RecordAck(context.Background(), CommandAck{ID: "c1", Success: true}); err != nil {
		t.Errorf("err: %v", err)
	}
}

func TestMemStorePolicyVersionRoundTrip(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	pv, err := s.SetPolicyVersion(ctx, "p1", "dsl1", "alice", "init")
	if err != nil {
		t.Fatal(err)
	}
	if pv.SHA == "" {
		t.Errorf("missing sha")
	}
	got, err := s.GetPolicyVersion(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if got.DSL != "dsl1" {
		t.Errorf("got %q", got.DSL)
	}

	if _, err := s.GetPolicyVersion(ctx, "absent"); err == nil {
		t.Errorf("expected error for missing")
	}

	if _, err := s.SetPolicyVersion(ctx, "p1", "dsl2", "bob", ""); err != nil {
		t.Fatal(err)
	}
	versions, _ := s.ListPolicyVersions(ctx, "p1", 10)
	if len(versions) != 2 {
		t.Errorf("len=%d", len(versions))
	}

	limited, _ := s.ListPolicyVersions(ctx, "p1", 1)
	if len(limited) != 1 {
		t.Errorf("limit ignored: %d", len(limited))
	}
}

func TestMemStoreNoOpMethods(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	if n, err := s.ExpireCommands(ctx, time.Hour); n != 0 || err != nil {
		t.Errorf("got %d %v", n, err)
	}
	if n, err := s.PruneAudit(ctx, time.Hour); n != 0 || err != nil {
		t.Errorf("got %d %v", n, err)
	}
	if n, err := s.TrimSnapshots(ctx, 10); n != 0 || err != nil {
		t.Errorf("got %d %v", n, err)
	}
	if b, err := s.BytesOnDisk(ctx); b != 0 || err != nil {
		t.Errorf("got %d %v", b, err)
	}
}

func TestSQLiteStoreRecordSnapshotAndTrim(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := store.RecordSnapshot(ctx, AgentSnapshot{
			Agent: AgentIdentity{InstanceID: "a1"},
			At:    time.Now().Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := store.TrimSnapshots(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("trimmed = %d", n)
	}
	if n2, _ := store.TrimSnapshots(ctx, 0); n2 != 0 {
		t.Errorf("zero keep should noop, got %d", n2)
	}
}

func TestSQLiteStoreBytesOnDisk(t *testing.T) {
	store := newTestStore(t)
	b, err := store.BytesOnDisk(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if b <= 0 {
		t.Errorf("expected positive bytes, got %d", b)
	}
}

func TestSQLiteStoreCommandIDRequired(t *testing.T) {
	store := newTestStore(t)
	if err := store.EnqueueCommand(context.Background(), "a", Command{}); err == nil {
		t.Errorf("expected error")
	}
}

func TestMemStoreClose(t *testing.T) {
	s := NewMemoryStore()
	if err := s.Close(); err != nil {
		t.Errorf("err: %v", err)
	}
}

func TestSQLiteStoreBytesOnDiskInMemory(t *testing.T) {
	store, err := NewSQLiteStore(context.Background(), ":memory:", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	b, err := store.BytesOnDisk(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if b < 0 {
		t.Errorf("expected non-negative, got %d", b)
	}
}

func TestMemStoreBytesOnDisk(t *testing.T) {
	s := NewMemoryStore()
	if b, err := s.BytesOnDisk(context.Background()); err != nil || b < 0 {
		t.Errorf("err=%v b=%d", err, b)
	}
}

func TestNewApprovalIDDifferentEachCall(t *testing.T) {
	a := newApprovalID("policy", "body", "finger")
	b := newApprovalID("policy", "body", "finger")
	if a == b {
		t.Errorf("expected different IDs (nonce), both = %q", a)
	}
	if len(a) == 0 {
		t.Errorf("empty id")
	}
}

func TestSQLiteStoreCreateApprovalValidations(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	if _, err := store.CreateApproval(ctx, PendingApproval{}); err == nil {
		t.Errorf("expected error for empty fields")
	}
	if _, err := store.CreateApproval(ctx, PendingApproval{PolicyName: "p", ProposedBody: "b"}); err == nil {
		t.Errorf("expected error for missing requester")
	}
}

func TestSQLiteStoreListTemplatesWithLabels(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	_, err := store.PublishTemplate(ctx, PolicyTemplate{
		Name: "t1",
		Body: "x",
		Labels: map[string]string{
			"env":  "prod",
			"team": "infra",
		},
		Publisher: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	tmpls, err := store.ListTemplates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpls) == 0 || tmpls[0].Labels["env"] != "prod" {
		t.Errorf("got %+v", tmpls)
	}
}

var _ = errors.New
