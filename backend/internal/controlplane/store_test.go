package controlplane

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) Store {
	t.Helper()
	dir := t.TempDir()
	store, err := NewSQLiteStore(context.Background(), filepath.Join(dir, "cp.db"), nil)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestSQLiteStoreAgentRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	id := AgentIdentity{
		InstanceID: "host-a",
		Hostname:   "host-a.example",
		Version:    "v1.0.0",
		Backend:    "nftables",
		Chain:      "FIREFIK",
		Labels:     map[string]string{"env": "prod"},
	}
	if err := store.UpsertAgent(ctx, id); err != nil {
		t.Fatal(err)
	}

	id2 := id
	id2.Hostname = "host-a2.example"
	if err := store.UpsertAgent(ctx, id2); err != nil {
		t.Fatal(err)
	}

	recs, err := store.ListAgents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 agent, got %d", len(recs))
	}
	if recs[0].Identity.Hostname != "host-a2.example" {
		t.Fatalf("upsert did not update hostname: %s", recs[0].Identity.Hostname)
	}
	if recs[0].Identity.Labels["env"] != "prod" {
		t.Fatalf("labels not persisted")
	}
}

func TestSQLiteStoreCommandLifecycle(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	_ = store.UpsertAgent(ctx, AgentIdentity{InstanceID: "a"})

	cmd := Command{ID: "c1", Kind: CommandApply, ContainerID: "abc", IssuedAt: time.Now().UTC()}
	if err := store.EnqueueCommand(ctx, "a", cmd); err != nil {
		t.Fatal(err)
	}

	first, err := store.TakeCommands(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].ID != "c1" {
		t.Fatalf("first take: %+v", first)
	}

	second, err := store.TakeCommands(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Fatalf("want empty, got %+v", second)
	}

	if err := store.RecordAck(ctx, CommandAck{ID: "c1", AgentID: "a", Success: true}); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteStoreExpireCommands(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	_ = store.UpsertAgent(ctx, AgentIdentity{InstanceID: "a"})

	old := Command{ID: "old", Kind: CommandApply, ContainerID: "x", IssuedAt: time.Now().Add(-48 * time.Hour)}
	fresh := Command{ID: "fresh", Kind: CommandApply, ContainerID: "y", IssuedAt: time.Now()}
	if err := store.EnqueueCommand(ctx, "a", old); err != nil {
		t.Fatal(err)
	}
	if err := store.EnqueueCommand(ctx, "a", fresh); err != nil {
		t.Fatal(err)
	}

	n, err := store.ExpireCommands(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 expired, got %d", n)
	}

	taken, err := store.TakeCommands(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(taken) != 1 || taken[0].ID != "fresh" {
		t.Fatalf("unexpected remaining: %+v", taken)
	}
}

func TestSQLiteStoreAuditPrune(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	_ = store.UpsertAgent(ctx, AgentIdentity{InstanceID: "a"})

	for i := 0; i < 3; i++ {
		if err := store.RecordAudit(ctx, "a", "apply",
			map[string]any{"seq": i},
			time.Now().Add(-time.Duration(48-i)*time.Hour),
		); err != nil {
			t.Fatal(err)
		}
	}

	n, err := store.PruneAudit(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatalf("expected some rows pruned, got %d", n)
	}
}

func TestSQLiteStorePolicyVersions(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	v1, err := store.SetPolicyVersion(ctx, "web", "policy \"web\" { allow port 80 }", "alice", "initial")
	if err != nil {
		t.Fatal(err)
	}
	if v1.SHA == "" {
		t.Fatalf("sha missing")
	}

	v2, err := store.SetPolicyVersion(ctx, "web", "policy \"web\" { allow port 80 }", "bob", "dup")
	if err != nil {
		t.Fatal(err)
	}
	if v1.SHA != v2.SHA {
		t.Fatalf("sha drifted: %s != %s", v1.SHA, v2.SHA)
	}

	time.Sleep(2 * time.Millisecond)
	if _, err := store.SetPolicyVersion(ctx, "web", "policy \"web\" { allow port 443 }", "bob", "update"); err != nil {
		t.Fatal(err)
	}
	history, err := store.ListPolicyVersions(ctx, "web", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("want 2 versions, got %d", len(history))
	}

	latest, err := store.GetPolicyVersion(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if latest.DSL == v1.DSL {
		t.Fatalf("latest returned the old version")
	}
}

func TestSQLiteStoreHydratesRegistry(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	_ = store.UpsertAgent(ctx, AgentIdentity{InstanceID: "hydrate-1", Hostname: "h1"})

	reg := NewRegistryWithStore(nil, store)
	agents := reg.Agents()
	if len(agents) != 1 || agents[0].Identity.InstanceID != "hydrate-1" {
		t.Fatalf("unexpected: %+v", agents)
	}
}

func TestNewSQLiteStore_EmptyPathDefaultsInMemory(t *testing.T) {
	store, err := NewSQLiteStore(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("empty path should default to :memory: → got %v", err)
	}
	if err := store.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestNewSQLiteStore_BadPath(t *testing.T) {
	_, err := NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "no-such-dir", "x.db"), nil)
	if err == nil {
		t.Fatal("expected error for missing parent dir")
	}
}

func TestRegistry_HydrateNilStoreNoop(t *testing.T) {
	r := &Registry{agents: map[string]*agentEntry{}}
	r.hydrate(context.Background())
}

func TestSQLiteStoreHydratesRegistry_WithLogger(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	_ = store.UpsertAgent(ctx, AgentIdentity{InstanceID: "hydrated-with-log", Hostname: "h2"})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := NewRegistryWithStore(logger, store)
	if len(reg.Agents()) != 1 {
		t.Fatalf("expected 1 agent hydrated, got %d", len(reg.Agents()))
	}
}

func TestSQLiteStoreCertRenewHistory(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)

	if _, ok, err := store.LastCertRenew(ctx, "deadbeef"); err != nil || ok {
		t.Fatalf("missing serial should return ok=false: ok=%v err=%v", ok, err)
	}

	t0 := time.Now().UTC().Truncate(time.Second)
	if err := store.RecordCertRenew(ctx, "deadbeef", "agent-a", t0); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.LastCertRenew(ctx, "deadbeef")
	if err != nil || !ok || !got.Equal(t0) {
		t.Fatalf("got=%v ok=%v err=%v", got, ok, err)
	}

	got, ok, err = store.LastCertRenew(ctx, "DEADBEEF")
	if err != nil || !ok || !got.Equal(t0) {
		t.Fatalf("case-insensitive lookup failed")
	}

	t1 := t0.Add(time.Minute)
	if err := store.RecordCertRenew(ctx, "deadbeef", "agent-a", t1); err != nil {
		t.Fatal(err)
	}
	got, _, _ = store.LastCertRenew(ctx, "deadbeef")
	if !got.Equal(t1) {
		t.Fatalf("upsert did not update timestamp: got=%v want=%v", got, t1)
	}

	if err := store.RecordCertRenew(ctx, "", "x", t0); err == nil {
		t.Fatal("empty serial should error")
	}

	if err := store.PruneCertRenewHistory(ctx, []string{"deadbeef", "missing"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.LastCertRenew(ctx, "deadbeef"); ok {
		t.Fatal("entry not pruned")
	}
	if err := store.PruneCertRenewHistory(ctx, nil); err != nil {
		t.Fatal(err)
	}
}

func TestMemStoreCertRenewHistory(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	t0 := time.Now().UTC().Truncate(time.Second)

	if _, ok, _ := store.LastCertRenew(ctx, ""); ok {
		t.Fatal("empty serial should miss")
	}
	if err := store.RecordCertRenew(ctx, "", "x", t0); err == nil {
		t.Fatal("empty serial should error")
	}
	if err := store.RecordCertRenew(ctx, "AbCd", "agent", t0); err != nil {
		t.Fatal(err)
	}
	got, ok, _ := store.LastCertRenew(ctx, "abcd")
	if !ok || !got.Equal(t0) {
		t.Fatalf("got=%v ok=%v", got, ok)
	}
	if err := store.PruneCertRenewHistory(ctx, []string{"abcd"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.LastCertRenew(ctx, "abcd"); ok {
		t.Fatal("not pruned")
	}
}
