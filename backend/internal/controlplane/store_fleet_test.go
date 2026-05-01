package controlplane

import (
	"context"
	"testing"
	"time"
)

func TestSQLite_LatestSnapshot_NilWhenAbsent(t *testing.T) {
	s, err := NewSQLiteStore(context.Background(), ":memory:", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	got, err := s.LatestSnapshot(context.Background(), "nope")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestSQLite_LatestSnapshot_ReturnsMostRecent(t *testing.T) {
	s, err := NewSQLiteStore(context.Background(), ":memory:", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id := AgentIdentity{InstanceID: "h1", Hostname: "h1"}
	earlier := AgentSnapshot{Agent: id, At: time.Now().UTC().Add(-time.Minute), Containers: []ContainerState{{ID: "old"}}}
	later := AgentSnapshot{Agent: id, At: time.Now().UTC(), Containers: []ContainerState{{ID: "new", Sources: []string{"label"}}}}

	if err := s.RecordSnapshot(context.Background(), earlier); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordSnapshot(context.Background(), later); err != nil {
		t.Fatal(err)
	}

	got, err := s.LatestSnapshot(context.Background(), "h1")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got.Containers) != 1 || got.Containers[0].ID != "new" {
		t.Fatalf("expected newest snapshot, got %+v", got)
	}
	if len(got.Containers[0].Sources) != 1 || got.Containers[0].Sources[0] != "label" {
		t.Fatalf("sources not preserved: %+v", got.Containers[0].Sources)
	}
}

func TestSQLite_EnrollmentToken_Lifecycle(t *testing.T) {
	s, err := NewSQLiteStore(context.Background(), ":memory:", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().UTC()
	tok := EnrollmentToken{
		Token: "t-1", AgentID: "h1", TTLSeconds: 600,
		ExpiresAt: now.Add(10 * time.Minute), IssuedBy: "op", IssuedAt: now,
	}
	if err := s.CreateEnrollmentToken(context.Background(), tok); err != nil {
		t.Fatal(err)
	}

	all, err := s.ListEnrollmentTokens(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Token != "t-1" {
		t.Fatalf("list mismatch: %+v", all)
	}

	got, err := s.ConsumeEnrollmentToken(context.Background(), "t-1", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if got.ConsumedAt == nil || got.ConsumerIP != "1.2.3.4" {
		t.Fatalf("consume not recorded: %+v", got)
	}

	if _, err := s.ConsumeEnrollmentToken(context.Background(), "t-1", ""); err == nil {
		t.Fatal("second consume must fail")
	}

	active, err := s.ListEnrollmentTokens(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("active list should hide consumed: %+v", active)
	}

	withUsed, err := s.ListEnrollmentTokens(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(withUsed) != 1 || withUsed[0].ConsumedAt == nil {
		t.Fatalf("include_used: %+v", withUsed)
	}
}

func TestSQLite_EnrollmentToken_Expired(t *testing.T) {
	s, err := NewSQLiteStore(context.Background(), ":memory:", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	past := time.Now().UTC().Add(-time.Hour)
	if err := s.CreateEnrollmentToken(context.Background(), EnrollmentToken{
		Token: "exp", AgentID: "h1", ExpiresAt: past, IssuedAt: past.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeEnrollmentToken(context.Background(), "exp", ""); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestSQLite_EnrollmentToken_NotFound(t *testing.T) {
	s, err := NewSQLiteStore(context.Background(), ":memory:", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.ConsumeEnrollmentToken(context.Background(), "nope", ""); err == nil {
		t.Fatal("expected not-found")
	}
}

func TestSQLite_EnrollmentToken_Revoke(t *testing.T) {
	s, err := NewSQLiteStore(context.Background(), ":memory:", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	if err := s.CreateEnrollmentToken(context.Background(), EnrollmentToken{
		Token: "rev", AgentID: "h1", ExpiresAt: now.Add(time.Hour), IssuedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeEnrollmentToken(context.Background(), "rev"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeEnrollmentToken(context.Background(), "rev", ""); err == nil {
		t.Fatal("expected revoked error")
	}
	if err := s.RevokeEnrollmentToken(context.Background(), "rev"); err == nil {
		t.Fatal("double revoke should fail")
	}
}

func TestMemStore_GetAgent(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	if err := s.UpsertAgent(ctx, AgentIdentity{InstanceID: "h1", Hostname: "h1", Backend: "nft"}); err != nil {
		t.Fatal(err)
	}
	rec, ok, err := s.GetAgent(ctx, "h1")
	if err != nil || !ok {
		t.Fatalf("got err=%v ok=%v", err, ok)
	}
	if rec.Identity.InstanceID != "h1" || rec.Identity.Backend != "nft" {
		t.Fatalf("identity not propagated: %+v", rec.Identity)
	}

	_, ok, err = s.GetAgent(ctx, "missing")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if ok {
		t.Fatal("expected ok=false for missing")
	}
}

func TestSQLiteStore_GetAgent(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSQLiteStore(t.Context(), dir+"/cp.db", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id := AgentIdentity{
		InstanceID: "host-prod-01",
		Hostname:   "host-prod-01",
		Version:    "0.15.0",
		Backend:    "nftables",
		Chain:      "FIREFIK",
		Labels:     map[string]string{"env": "prod"},
	}
	if err := s.UpsertAgent(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	rec, ok, err := s.GetAgent(t.Context(), "host-prod-01")
	if err != nil || !ok {
		t.Fatalf("got err=%v ok=%v", err, ok)
	}
	if rec.Identity.Backend != "nftables" || rec.Identity.Labels["env"] != "prod" {
		t.Fatalf("identity not roundtripped: %+v", rec.Identity)
	}
	if rec.HasSnapshot {
		t.Fatal("expected has_snapshot=false")
	}

	snap := AgentSnapshot{Agent: id, At: time.Now().UTC(), Containers: []ContainerState{{ID: "c1"}}}
	if err := s.RecordSnapshot(t.Context(), snap); err != nil {
		t.Fatal(err)
	}
	rec, ok, err = s.GetAgent(t.Context(), "host-prod-01")
	if err != nil || !ok {
		t.Fatalf("got err=%v ok=%v", err, ok)
	}
	if !rec.HasSnapshot {
		t.Fatal("expected has_snapshot=true after RecordSnapshot")
	}

	_, ok, err = s.GetAgent(t.Context(), "no-such-host")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if ok {
		t.Fatal("expected ok=false for missing")
	}
}
