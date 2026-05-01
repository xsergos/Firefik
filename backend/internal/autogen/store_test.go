package autogen

import (
	"context"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

func newStores(t *testing.T) map[string]func(t *testing.T) Store {
	t.Helper()
	return map[string]func(t *testing.T) Store{
		"memory": func(t *testing.T) Store {
			return NewMemoryStore()
		},
		"sqlite_memory": func(t *testing.T) Store {
			st, err := NewSQLiteStore(context.Background(), ":memory:", nil)
			if err != nil {
				t.Fatalf("NewSQLiteStore(:memory:) failed: %v", err)
			}
			t.Cleanup(func() { _ = st.Close() })
			return st
		},
		"sqlite_file": func(t *testing.T) Store {
			dir := t.TempDir()
			path := filepath.Join(dir, "autogen.db")
			st, err := NewSQLiteStore(context.Background(), path, nil)
			if err != nil {
				t.Fatalf("NewSQLiteStore(file) failed: %v", err)
			}
			t.Cleanup(func() { _ = st.Close() })
			return st
		},
	}
}

func TestNewSQLiteStoreEmptyPathUsesMemory(t *testing.T) {
	st, err := NewSQLiteStore(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("NewSQLiteStore with empty path failed: %v", err)
	}
	defer func() { _ = st.Close() }()

	if err := st.Observe(context.Background(), Flow{
		ContainerID: "c1", Protocol: "tcp", Port: 80, PeerIP: "1.1.1.1", At: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Observe on empty-path store failed: %v", err)
	}
}

func TestNewSQLiteStoreMigrationIdempotence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mig.db")

	st1, err := NewSQLiteStore(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("first open failed: %v", err)
	}
	if err := st1.Close(); err != nil {
		t.Fatalf("first close failed: %v", err)
	}

	st2, err := NewSQLiteStore(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("second open (re-migration) failed: %v", err)
	}
	defer func() { _ = st2.Close() }()

	if err := st2.Observe(context.Background(), Flow{
		ContainerID: "c1", Protocol: "tcp", Port: 80, At: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Observe after re-open failed: %v", err)
	}
}

func TestNewSQLiteStoreBadPath(t *testing.T) {
	bad := filepath.Join("does", "not", "exist", "nowhere", "ag.db")
	_, err := NewSQLiteStore(context.Background(), bad, nil)
	if err == nil {
		t.Fatalf("expected error opening db under missing directory tree, got nil")
	}
}

func TestObserveRequiresContainerID(t *testing.T) {
	for name, factory := range newStores(t) {
		t.Run(name, func(t *testing.T) {
			st := factory(t)
			err := st.Observe(context.Background(), Flow{Protocol: "tcp", Port: 80, PeerIP: "1.1.1.1"})
			if err == nil {
				t.Fatalf("expected error when container_id empty")
			}
		})
	}
}

func TestObserveAssignsTimestampWhenZero(t *testing.T) {
	for name, factory := range newStores(t) {
		t.Run(name, func(t *testing.T) {
			st := factory(t)
			if err := st.Observe(context.Background(), Flow{
				ContainerID: "cx", Protocol: "tcp", Port: 22, PeerIP: "9.9.9.9",
			}); err != nil {
				t.Fatalf("Observe failed: %v", err)
			}
			snap, err := st.SnapshotByContainer(context.Background(), "cx")
			if err != nil {
				t.Fatalf("SnapshotByContainer failed: %v", err)
			}
			if snap.Updated.IsZero() {
				t.Fatalf("expected Updated to be populated")
			}
			p := snap.Ports["tcp/22"]
			if p == nil || p.LastAt.IsZero() || p.FirstAt.IsZero() {
				t.Fatalf("port observation timestamps should be set, got %+v", p)
			}
		})
	}
}

func TestSnapshotByContainerEmpty(t *testing.T) {
	for name, factory := range newStores(t) {
		t.Run(name, func(t *testing.T) {
			st := factory(t)
			snap, err := st.SnapshotByContainer(context.Background(), "missing")
			if err != nil {
				t.Fatalf("SnapshotByContainer: %v", err)
			}
			if len(snap.Ports) != 0 {
				t.Fatalf("expected no ports, got %d", len(snap.Ports))
			}
			if len(snap.Peers) != 0 {
				t.Fatalf("expected no peers, got %d", len(snap.Peers))
			}
		})
	}
}

func TestObserveAggregatesSameTuple(t *testing.T) {
	for name, factory := range newStores(t) {
		t.Run(name, func(t *testing.T) {
			st := factory(t)
			base := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
			for i := 0; i < 5; i++ {
				if err := st.Observe(context.Background(), Flow{
					ContainerID: "aggr", Protocol: "tcp", Port: 443, PeerIP: "8.8.8.8",
					At: base.Add(time.Duration(i) * time.Second),
				}); err != nil {
					t.Fatalf("Observe #%d failed: %v", i, err)
				}
			}
			snap, err := st.SnapshotByContainer(context.Background(), "aggr")
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			p, ok := snap.Ports["tcp/443"]
			if !ok {
				t.Fatalf("expected tcp/443 in ports, got keys %v", keysOfPorts(snap.Ports))
			}
			if p.Count != 5 {
				t.Fatalf("expected coalesced count=5, got %d", p.Count)
			}
			if !p.FirstAt.Equal(base) {
				t.Fatalf("first_at should be initial observation, got %v", p.FirstAt)
			}
			if !p.LastAt.Equal(base.Add(4 * time.Second)) {
				t.Fatalf("last_at should be last observation, got %v", p.LastAt)
			}
			pe, ok := snap.Peers["8.8.8.8"]
			if !ok {
				t.Fatalf("peer missing from snapshot")
			}
			if pe.Count != 5 {
				t.Fatalf("expected peer count=5, got %d", pe.Count)
			}
		})
	}
}

func TestObserveDifferentTuplesDistinct(t *testing.T) {
	for name, factory := range newStores(t) {
		t.Run(name, func(t *testing.T) {
			st := factory(t)
			now := time.Now().UTC()
			flows := []Flow{
				{ContainerID: "multi", Protocol: "tcp", Port: 80, PeerIP: "1.1.1.1", At: now},
				{ContainerID: "multi", Protocol: "tcp", Port: 443, PeerIP: "1.1.1.1", At: now},
				{ContainerID: "multi", Protocol: "udp", Port: 53, PeerIP: "8.8.8.8", At: now},
				{ContainerID: "multi", Protocol: "tcp", Port: 80, PeerIP: "2.2.2.2", At: now},
			}
			for i, f := range flows {
				if err := st.Observe(context.Background(), f); err != nil {
					t.Fatalf("Observe %d: %v", i, err)
				}
			}
			snap, err := st.SnapshotByContainer(context.Background(), "multi")
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			wantPorts := []string{"tcp/443", "tcp/80", "udp/53"}
			gotPorts := keysOfPorts(snap.Ports)
			sort.Strings(gotPorts)
			if !equalStringSlice(gotPorts, wantPorts) {
				t.Fatalf("ports keys = %v, want %v", gotPorts, wantPorts)
			}
			if snap.Ports["tcp/80"].Count != 2 {
				t.Fatalf("tcp/80 count = %d, want 2 (two peers)", snap.Ports["tcp/80"].Count)
			}
			if len(snap.Peers) != 3 {
				t.Fatalf("expected 3 distinct peers (1.1.1.1, 8.8.8.8, 2.2.2.2), got %d", len(snap.Peers))
			}
			if snap.Peers["1.1.1.1"].Count != 2 {
				t.Fatalf("peer 1.1.1.1 count = %d, want 2 (appears in two flows)", snap.Peers["1.1.1.1"].Count)
			}
		})
	}
}

func TestSnapshotAcrossContainers(t *testing.T) {
	for name, factory := range newStores(t) {
		t.Run(name, func(t *testing.T) {
			st := factory(t)
			now := time.Now().UTC()
			_ = st.Observe(context.Background(), Flow{ContainerID: "A", Protocol: "tcp", Port: 80, PeerIP: "1.1.1.1", At: now})
			_ = st.Observe(context.Background(), Flow{ContainerID: "B", Protocol: "tcp", Port: 22, PeerIP: "2.2.2.2", At: now})
			_ = st.Observe(context.Background(), Flow{ContainerID: "B", Protocol: "udp", Port: 53, At: now})

			all, err := st.Snapshot(context.Background())
			if err != nil {
				t.Fatalf("Snapshot: %v", err)
			}
			if len(all) != 2 {
				t.Fatalf("expected 2 containers, got %d", len(all))
			}
			if _, ok := all["A"].Ports["tcp/80"]; !ok {
				t.Fatalf("A missing tcp/80")
			}
			if _, ok := all["B"].Ports["udp/53"]; !ok {
				t.Fatalf("B missing udp/53")
			}
			if _, hasPeer := all["B"].Peers[""]; hasPeer {
				t.Fatalf("empty peer_ip should not be tracked as a peer")
			}
		})
	}
}

func TestUpsertAndListProposals(t *testing.T) {
	for name, factory := range newStores(t) {
		t.Run(name, func(t *testing.T) {
			st := factory(t)
			p := Proposal{
				ContainerID: "c-1",
				Ports:       []uint16{80, 443},
				Peers:       []string{"1.1.1.1"},
				Confidence:  "moderate",
				ObservedFor: "1h0m0s",
			}
			if err := st.UpsertProposal(context.Background(), p); err != nil {
				t.Fatalf("UpsertProposal: %v", err)
			}
			recs, err := st.ListProposals(context.Background())
			if err != nil {
				t.Fatalf("ListProposals: %v", err)
			}
			if len(recs) != 1 {
				t.Fatalf("expected 1 record, got %d", len(recs))
			}
			got := recs[0]
			if got.ContainerID != "c-1" {
				t.Fatalf("container = %q", got.ContainerID)
			}
			if got.Status != StatusPending {
				t.Fatalf("status = %q, want pending", got.Status)
			}
			if len(got.Ports) != 2 || got.Ports[0] != 80 || got.Ports[1] != 443 {
				t.Fatalf("ports = %v", got.Ports)
			}
			if len(got.Peers) != 1 || got.Peers[0] != "1.1.1.1" {
				t.Fatalf("peers = %v", got.Peers)
			}
			if got.Confidence != "moderate" {
				t.Fatalf("confidence = %q", got.Confidence)
			}
			if got.ObservedFor != "1h0m0s" {
				t.Fatalf("observed_for = %q", got.ObservedFor)
			}
			if got.GeneratedAt.IsZero() {
				t.Fatalf("generated_at should be set")
			}
		})
	}
}

func TestUpsertProposalPreservesDecision(t *testing.T) {
	for name, factory := range newStores(t) {
		t.Run(name, func(t *testing.T) {
			st := factory(t)
			ctx := context.Background()
			p := Proposal{ContainerID: "keep", Ports: []uint16{80}, Confidence: "high"}
			if err := st.UpsertProposal(ctx, p); err != nil {
				t.Fatalf("upsert: %v", err)
			}
			if err := st.MarkProposal(ctx, "keep", StatusApproved, "alice", "looks ok"); err != nil {
				t.Fatalf("mark: %v", err)
			}
			p.Ports = []uint16{80, 443}
			p.Confidence = "moderate"
			if err := st.UpsertProposal(ctx, p); err != nil {
				t.Fatalf("re-upsert: %v", err)
			}
			recs, err := st.ListProposals(ctx)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(recs) != 1 {
				t.Fatalf("expected 1 record, got %d", len(recs))
			}
			got := recs[0]
			if got.Status != StatusApproved {
				t.Fatalf("status = %q, want approved (decision must be preserved)", got.Status)
			}
			if got.DecidedBy != "alice" {
				t.Fatalf("decided_by = %q, want alice", got.DecidedBy)
			}
			if got.Reason != "looks ok" {
				t.Fatalf("reason = %q", got.Reason)
			}
			if len(got.Ports) != 2 {
				t.Fatalf("ports should have been refreshed to 2, got %v", got.Ports)
			}
			if got.Confidence != "moderate" {
				t.Fatalf("confidence should be refreshed, got %q", got.Confidence)
			}
		})
	}
}

func TestMarkProposalTransitions(t *testing.T) {
	for name, factory := range newStores(t) {
		t.Run(name, func(t *testing.T) {
			st := factory(t)
			ctx := context.Background()
			_ = st.UpsertProposal(ctx, Proposal{ContainerID: "a", Ports: []uint16{80}, Confidence: "moderate"})
			_ = st.UpsertProposal(ctx, Proposal{ContainerID: "b", Ports: []uint16{22}, Confidence: "moderate"})
			_ = st.UpsertProposal(ctx, Proposal{ContainerID: "c", Ports: []uint16{53}, Confidence: "moderate"})

			if err := st.MarkProposal(ctx, "a", StatusApproved, "bob", "approved"); err != nil {
				t.Fatalf("approve: %v", err)
			}
			if err := st.MarkProposal(ctx, "b", StatusRejected, "bob", "not now"); err != nil {
				t.Fatalf("reject: %v", err)
			}
			if err := st.MarkProposal(ctx, "c", StatusExpired, "system", "age"); err != nil {
				t.Fatalf("expire: %v", err)
			}

			all, err := st.ListProposals(ctx)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			byID := map[string]ProposalRecord{}
			for _, r := range all {
				byID[r.ContainerID] = r
			}
			if byID["a"].Status != StatusApproved || byID["a"].DecidedBy != "bob" || byID["a"].Reason != "approved" {
				t.Fatalf("a = %+v", byID["a"])
			}
			if byID["b"].Status != StatusRejected {
				t.Fatalf("b status = %q", byID["b"].Status)
			}
			if byID["c"].Status != StatusExpired {
				t.Fatalf("c status = %q", byID["c"].Status)
			}
			if byID["a"].DecidedAt.IsZero() {
				t.Fatalf("decided_at should be set after Mark")
			}
		})
	}
}

func TestListProposalsStatusFilter(t *testing.T) {
	for name, factory := range newStores(t) {
		t.Run(name, func(t *testing.T) {
			st := factory(t)
			ctx := context.Background()
			_ = st.UpsertProposal(ctx, Proposal{ContainerID: "p1", Ports: []uint16{80}, Confidence: "moderate"})
			_ = st.UpsertProposal(ctx, Proposal{ContainerID: "p2", Ports: []uint16{81}, Confidence: "moderate"})
			_ = st.UpsertProposal(ctx, Proposal{ContainerID: "p3", Ports: []uint16{82}, Confidence: "moderate"})
			_ = st.MarkProposal(ctx, "p1", StatusApproved, "op", "")
			_ = st.MarkProposal(ctx, "p3", StatusRejected, "op", "")

			pending, err := st.ListProposals(ctx, StatusPending)
			if err != nil {
				t.Fatalf("list pending: %v", err)
			}
			if len(pending) != 1 || pending[0].ContainerID != "p2" {
				t.Fatalf("pending = %+v", pending)
			}
			approved, err := st.ListProposals(ctx, StatusApproved)
			if err != nil {
				t.Fatalf("list approved: %v", err)
			}
			if len(approved) != 1 || approved[0].ContainerID != "p1" {
				t.Fatalf("approved = %+v", approved)
			}
			decided, err := st.ListProposals(ctx, StatusApproved, StatusRejected)
			if err != nil {
				t.Fatalf("list decided: %v", err)
			}
			if len(decided) != 2 {
				t.Fatalf("decided len = %d, want 2", len(decided))
			}
		})
	}
}

func TestListProposalsOrderedByGeneratedDesc(t *testing.T) {
	for name, factory := range newStores(t) {
		t.Run(name, func(t *testing.T) {
			st := factory(t)
			ctx := context.Background()
			_ = st.UpsertProposal(ctx, Proposal{ContainerID: "first", Confidence: "moderate"})
			time.Sleep(10 * time.Millisecond)
			_ = st.UpsertProposal(ctx, Proposal{ContainerID: "second", Confidence: "moderate"})
			time.Sleep(10 * time.Millisecond)
			_ = st.UpsertProposal(ctx, Proposal{ContainerID: "third", Confidence: "moderate"})

			recs, err := st.ListProposals(ctx)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(recs) != 3 {
				t.Fatalf("len = %d", len(recs))
			}
			if recs[0].ContainerID != "third" || recs[1].ContainerID != "second" || recs[2].ContainerID != "first" {
				t.Fatalf("ordering wrong: %v", []string{recs[0].ContainerID, recs[1].ContainerID, recs[2].ContainerID})
			}
		})
	}
}

func TestMarkProposalRequiresContainerID(t *testing.T) {
	for name, factory := range newStores(t) {
		t.Run(name, func(t *testing.T) {
			st := factory(t)
			err := st.MarkProposal(context.Background(), "", StatusApproved, "op", "")
			if name == "memory" {
				if err == nil {
					t.Fatalf("memory store should error (no such proposal)")
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error for empty container_id on sqlite store")
			}
		})
	}
}

func TestMarkProposalMemoryMissing(t *testing.T) {
	st := NewMemoryStore()
	err := st.MarkProposal(context.Background(), "nope", StatusApproved, "op", "")
	if err == nil {
		t.Fatalf("expected error when marking missing proposal in memory store")
	}
}

func TestMinSamplesThresholdEmitsProposal(t *testing.T) {
	for name, factory := range newStores(t) {
		t.Run(name, func(t *testing.T) {
			st := factory(t)
			ctx := context.Background()
			obs := NewObserverWithStore(st)
			base := time.Now().Add(-2 * time.Minute)
			for i := 0; i < 4; i++ {
				obs.Record(Flow{ContainerID: "under", Protocol: "tcp", Port: 80, PeerIP: "1.1.1.1", At: base.Add(time.Duration(i) * time.Second)})
			}
			for i := 0; i < 10; i++ {
				obs.Record(Flow{ContainerID: "over", Protocol: "tcp", Port: 443, PeerIP: "2.2.2.2", At: base.Add(time.Duration(i) * time.Second)})
			}
			proposals := obs.Propose(5, 0)
			if len(proposals) != 1 {
				t.Fatalf("expected 1 proposal above min-samples, got %d: %+v", len(proposals), proposals)
			}
			if proposals[0].ContainerID != "over" {
				t.Fatalf("proposal container = %q, want over", proposals[0].ContainerID)
			}
			for _, p := range proposals {
				if err := st.UpsertProposal(ctx, p); err != nil {
					t.Fatalf("persist proposal: %v", err)
				}
			}
			recs, err := st.ListProposals(ctx, StatusPending)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(recs) != 1 || recs[0].ContainerID != "over" {
				t.Fatalf("persisted proposals = %+v", recs)
			}
		})
	}
}

func TestPruneObservations(t *testing.T) {
	t.Run("sqlite_memory", func(t *testing.T) {
		st, err := NewSQLiteStore(context.Background(), ":memory:", nil)
		if err != nil {
			t.Fatalf("NewSQLiteStore: %v", err)
		}
		defer func() { _ = st.Close() }()
		ctx := context.Background()

		oldTime := time.Now().UTC().Add(-2 * time.Hour)
		if err := st.Observe(ctx, Flow{ContainerID: "old", Protocol: "tcp", Port: 80, PeerIP: "1.1.1.1", At: oldTime}); err != nil {
			t.Fatalf("observe old: %v", err)
		}
		if err := st.Observe(ctx, Flow{ContainerID: "new", Protocol: "tcp", Port: 80, PeerIP: "2.2.2.2", At: time.Now().UTC()}); err != nil {
			t.Fatalf("observe new: %v", err)
		}

		zero, err := st.PruneObservations(ctx, 0)
		if err != nil {
			t.Fatalf("prune(0): %v", err)
		}
		if zero != 0 {
			t.Fatalf("prune(0) removed %d rows, want 0", zero)
		}
		neg, err := st.PruneObservations(ctx, -time.Second)
		if err != nil {
			t.Fatalf("prune(<0): %v", err)
		}
		if neg != 0 {
			t.Fatalf("prune(<0) removed %d rows, want 0", neg)
		}

		removed, err := st.PruneObservations(ctx, time.Hour)
		if err != nil {
			t.Fatalf("prune(1h): %v", err)
		}
		if removed != 1 {
			t.Fatalf("prune(1h) removed %d rows, want 1", removed)
		}

		all, err := st.Snapshot(ctx)
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		if _, ok := all["old"]; ok {
			t.Fatalf("old container should be pruned")
		}
		if _, ok := all["new"]; !ok {
			t.Fatalf("new container should remain")
		}
	})

	t.Run("memory", func(t *testing.T) {
		st := NewMemoryStore()
		n, err := st.PruneObservations(context.Background(), time.Hour)
		if err != nil {
			t.Fatalf("memory prune: %v", err)
		}
		if n != 0 {
			t.Fatalf("memory prune always returns 0, got %d", n)
		}
	})
}

func TestCloseIsSafe(t *testing.T) {
	m := NewMemoryStore()
	if err := m.Close(); err != nil {
		t.Fatalf("memory close: %v", err)
	}

	s, err := NewSQLiteStore(context.Background(), ":memory:", nil)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("sqlite close: %v", err)
	}
}

func TestConcurrentObserve(t *testing.T) {
	for name, factory := range newStores(t) {
		t.Run(name, func(t *testing.T) {
			st := factory(t)
			ctx := context.Background()
			const workers = 8
			const perWorker = 50
			var wg sync.WaitGroup
			start := time.Now().UTC()
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(worker int) {
					defer wg.Done()
					for i := 0; i < perWorker; i++ {
						_ = st.Observe(ctx, Flow{
							ContainerID: "race",
							Protocol:    "tcp",
							Port:        80,
							PeerIP:      "10.0.0.1",
							At:          start.Add(time.Duration(worker*perWorker+i) * time.Millisecond),
						})
					}
				}(w)
			}
			wg.Wait()
			snap, err := st.SnapshotByContainer(ctx, "race")
			if err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			p, ok := snap.Ports["tcp/80"]
			if !ok {
				t.Fatalf("missing tcp/80 after concurrent writes")
			}
			if p.Count != workers*perWorker {
				t.Fatalf("count = %d, want %d", p.Count, workers*perWorker)
			}
			pe, ok := snap.Peers["10.0.0.1"]
			if !ok {
				t.Fatalf("peer missing")
			}
			if pe.Count != workers*perWorker {
				t.Fatalf("peer count = %d, want %d", pe.Count, workers*perWorker)
			}
		})
	}
}

func TestSnapshotByContainerIsCopyForMemoryStore(t *testing.T) {
	st := NewMemoryStore()
	ctx := context.Background()
	_ = st.Observe(ctx, Flow{ContainerID: "c", Protocol: "tcp", Port: 80, PeerIP: "1.1.1.1", At: time.Now().UTC()})
	snap1, err := st.SnapshotByContainer(ctx, "c")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if p := snap1.Ports["tcp/80"]; p != nil {
		p.Count = 9999
	}
	snap2, err := st.SnapshotByContainer(ctx, "c")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap2.Ports["tcp/80"].Count == 9999 {
		t.Fatalf("memory store SnapshotByContainer should return an independent copy")
	}
}

func TestSnapshotReturnsCopyForMemoryStore(t *testing.T) {
	st := NewMemoryStore()
	ctx := context.Background()
	_ = st.Observe(ctx, Flow{ContainerID: "c", Protocol: "tcp", Port: 80, PeerIP: "1.1.1.1", At: time.Now().UTC()})
	all1, err := st.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	all1["c"].Ports["tcp/80"].Count = 12345
	all2, err := st.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if all2["c"].Ports["tcp/80"].Count == 12345 {
		t.Fatalf("memory Snapshot should return an independent deep copy")
	}
}

func keysOfPorts(m map[string]*PortObservation) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
