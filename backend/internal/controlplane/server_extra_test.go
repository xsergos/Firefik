package controlplane

import (
	"context"
	"testing"
	"time"
)

func TestRegistryStore(t *testing.T) {
	store := newTestStore(t)
	reg := NewRegistryWithStore(nil, store)
	if reg.Store() != store {
		t.Errorf("Store mismatch")
	}
}

func TestRegistryStoreNotNil(t *testing.T) {
	reg := NewRegistry(nil)
	if reg.Store() == nil {
		t.Errorf("expected memStore default")
	}
}

func TestRegistryNoStoreCustom(t *testing.T) {
	reg := NewRegistryWithStore(nil, nil)
	if reg.Store() != nil {
		t.Errorf("expected nil store")
	}
	reg.RecordSnapshot(AgentSnapshot{Agent: AgentIdentity{InstanceID: "a"}})
	reg.RecordAuditEvent(AuditEventEnvelope{Agent: AgentIdentity{InstanceID: "a"}})
}

func TestRegistryRecordSnapshotNoStore(t *testing.T) {
	reg := NewRegistryWithStore(nil, nil)
	reg.RecordSnapshot(AgentSnapshot{Agent: AgentIdentity{InstanceID: "a"}})
}

func TestRegistryRecordSnapshotWithStore(t *testing.T) {
	store := newTestStore(t)
	reg := NewRegistryWithStore(nil, store)
	reg.RecordSnapshot(AgentSnapshot{Agent: AgentIdentity{InstanceID: "a"}, At: time.Now()})
}

func TestRegistryRecordAuditEventNoStore(t *testing.T) {
	reg := NewRegistryWithStore(nil, nil)
	reg.RecordAuditEvent(AuditEventEnvelope{Agent: AgentIdentity{InstanceID: "a"}})
}

func TestRegistryRecordAuditEventWithStore(t *testing.T) {
	store := newTestStore(t)
	reg := NewRegistryWithStore(nil, store)
	_ = store.UpsertAgent(context.Background(), AgentIdentity{InstanceID: "a"})
	reg.RecordAuditEvent(AuditEventEnvelope{
		Agent: AgentIdentity{InstanceID: "a"},
		Event: map[string]any{"action": "apply"},
	})
}

func TestRunRetentionLoopNoStore(t *testing.T) {
	reg := NewRegistryWithStore(nil, nil)
	if err := reg.RunRetentionLoop(context.Background(), time.Second, time.Hour, time.Hour, 100); err != nil {
		t.Errorf("err: %v", err)
	}
}

func TestRunRetentionLoopZeroInterval(t *testing.T) {
	store := newTestStore(t)
	reg := NewRegistryWithStore(nil, store)
	if err := reg.RunRetentionLoop(context.Background(), 0, time.Hour, time.Hour, 100); err != nil {
		t.Errorf("err: %v", err)
	}
}

func TestRunRetentionLoopCancellation(t *testing.T) {
	store := newTestStore(t)
	reg := NewRegistryWithStore(nil, store)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := reg.RunRetentionLoop(ctx, 5*time.Millisecond, time.Hour, time.Hour, 100); err != nil {
		t.Errorf("err: %v", err)
	}
}
