package agentdispatch

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"firefik/internal/api"
	"firefik/internal/audit"
	"firefik/internal/autogen"
	"firefik/internal/config"
	"firefik/internal/controlplane"
	"firefik/internal/docker"
	"firefik/internal/rules"
)

type fakeDockerReader struct {
	containers []docker.ContainerInfo
	listErr    error
}

func (f *fakeDockerReader) ListContainers(_ context.Context) ([]docker.ContainerInfo, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]docker.ContainerInfo{}, f.containers...), nil
}

func (f *fakeDockerReader) Inspect(_ context.Context, id string) (docker.ContainerInfo, bool, error) {
	for _, c := range f.containers {
		if c.ID == id {
			return c, true, nil
		}
	}
	return docker.ContainerInfo{}, false, nil
}

type trafficAdapter struct{ store *api.TrafficStore }

func (a *trafficAdapter) Last(n int) []TrafficBucket {
	out := make([]TrafficBucket, 0, n)
	for _, b := range a.store.Last(n) {
		out = append(out, TrafficBucket{Timestamp: b.Timestamp, Accepted: b.Accepted, Dropped: b.Dropped})
	}
	return out
}

func newTestDispatcher(t *testing.T) (*Dispatcher, *fakeDockerReader, *autogen.Observer) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{ChainName: "FIREFIK", EffectiveChain: "FIREFIK", Backend: "iptables"}
	dr := &fakeDockerReader{containers: []docker.ContainerInfo{
		{ID: "c1", Name: "web", Status: "running", Labels: map[string]string{"firefik.enable": "true"}},
		{ID: "c2", Name: "db", Status: "exited"},
	}}
	engine := rules.NewEngine(nil, dr, cfg, logger)
	obs := autogen.NewObserver()
	store := api.NewTrafficStore()
	store.RecordAction("ACCEPT")
	store.RecordAction("DROP")
	d := New(Deps{
		Engine:   engine,
		Docker:   dr,
		Config:   cfg,
		Traffic:  &trafficAdapter{store: store},
		Observer: obs,
		Logger:   logger,
	})
	return d, dr, obs
}

func TestDispatcher_StatsCollect(t *testing.T) {
	d, _, _ := newTestDispatcher(t)
	ack := d.Dispatch(context.Background(), controlplane.Command{
		ID:   "cmd1",
		Kind: controlplane.CommandStatsCollect,
	})
	if !ack.Success {
		t.Fatalf("expected success, got %q", ack.Error)
	}
	if ack.ResultPayload == nil {
		t.Fatal("expected result_payload")
	}
	containers, ok := ack.ResultPayload["containers"].(map[string]any)
	if !ok {
		t.Fatalf("missing containers: %+v", ack.ResultPayload)
	}
	if total, _ := containers["total"].(int); total != 2 {
		t.Errorf("total: %v", containers["total"])
	}
}

func TestDispatcher_StatsCollect_DockerError(t *testing.T) {
	d, dr, _ := newTestDispatcher(t)
	dr.listErr = errors.New("docker boom")
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "x", Kind: controlplane.CommandStatsCollect})
	if ack.Success {
		t.Fatal("expected failure")
	}
}

func TestDispatcher_StatsCollect_NoDocker(t *testing.T) {
	d, _, _ := newTestDispatcher(t)
	d.deps.Docker = nil
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "x", Kind: controlplane.CommandStatsCollect})
	if ack.Success {
		t.Fatal("expected failure")
	}
}

func TestDispatcher_AutogenApprove_NoObserver(t *testing.T) {
	d, _, _ := newTestDispatcher(t)
	d.deps.Observer = nil
	ack := d.Dispatch(context.Background(), controlplane.Command{
		ID: "x", Kind: controlplane.CommandAutogenApprove, ContainerID: "c1",
		Payload: map[string]any{"mode": "labels"},
	})
	if ack.Success {
		t.Fatal("expected failure")
	}
	if !strings.Contains(ack.Error, "autogen") {
		t.Fatalf("error should mention autogen, got %q", ack.Error)
	}
}

func TestDispatcher_AutogenApprove_NoProposal(t *testing.T) {
	d, _, _ := newTestDispatcher(t)
	ack := d.Dispatch(context.Background(), controlplane.Command{
		ID: "x", Kind: controlplane.CommandAutogenApprove, ContainerID: "no-such",
		Payload: map[string]any{"mode": "labels"},
	})
	if ack.Success {
		t.Fatal("expected failure")
	}
}

func TestDispatcher_AutogenApprove_BadMode(t *testing.T) {
	d, _, _ := newTestDispatcher(t)
	ack := d.Dispatch(context.Background(), controlplane.Command{
		ID: "x", Kind: controlplane.CommandAutogenApprove, ContainerID: "c1",
		Payload: map[string]any{"mode": "weird"},
	})
	if ack.Success {
		t.Fatal("expected failure")
	}
}

func TestDispatcher_AutogenApprove_MissingContainerID(t *testing.T) {
	d, _, _ := newTestDispatcher(t)
	ack := d.Dispatch(context.Background(), controlplane.Command{
		ID: "x", Kind: controlplane.CommandAutogenApprove,
	})
	if ack.Success {
		t.Fatal("expected failure")
	}
}

func TestDispatcher_AutogenReject_NoObserver(t *testing.T) {
	d, _, _ := newTestDispatcher(t)
	d.deps.Observer = nil
	ack := d.Dispatch(context.Background(), controlplane.Command{
		ID: "x", Kind: controlplane.CommandAutogenReject, ContainerID: "c1",
		Payload: map[string]any{"reason": "test"},
	})
	if ack.Success {
		t.Fatal("expected failure")
	}
}

func TestDispatcher_AutogenReject_MissingContainerID(t *testing.T) {
	d, _, _ := newTestDispatcher(t)
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "x", Kind: controlplane.CommandAutogenReject})
	if ack.Success {
		t.Fatal("expected failure")
	}
}

func TestDispatcher_Apply_RequiresContainer(t *testing.T) {
	d := New(Deps{Logger: slog.Default()})
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "1", Kind: controlplane.CommandApply})
	if ack.Success {
		t.Fatal("expected failure")
	}
}

func TestDispatcher_Disable_RequiresContainer(t *testing.T) {
	d := New(Deps{Logger: slog.Default()})
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "1", Kind: controlplane.CommandDisable})
	if ack.Success {
		t.Fatal("expected failure")
	}
}

func TestDispatcher_TokenRotate_Rejected(t *testing.T) {
	d := New(Deps{Logger: slog.Default()})
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "x", Kind: controlplane.CommandTokenRotate})
	if ack.Success {
		t.Fatal("token-rotate must be rejected over CP")
	}
}

func TestDispatcher_UnknownKind(t *testing.T) {
	d := New(Deps{Logger: slog.Default()})
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "1", Kind: "voodoo"})
	if ack.Success {
		t.Fatal("expected failure")
	}
}

type fakeEngine struct {
	applyErr     error
	removeErr    error
	reconcileErr error
	applied      map[string]docker.ContainerConfig
}

func (f *fakeEngine) ApplyContainer(_ context.Context, _ string, _ audit.Source) error {
	return f.applyErr
}
func (f *fakeEngine) RemoveContainer(_ string, _ audit.Source) error { return f.removeErr }
func (f *fakeEngine) Reconcile(_ context.Context, _ audit.Source) error {
	return f.reconcileErr
}
func (f *fakeEngine) GetApplied() map[string]docker.ContainerConfig { return f.applied }

func TestDispatcher_Apply_Success(t *testing.T) {
	d := New(Deps{Engine: &fakeEngine{}, Logger: slog.Default()})
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "1", Kind: controlplane.CommandApply, ContainerID: "c1"})
	if !ack.Success {
		t.Fatalf("expected success: %s", ack.Error)
	}
}

func TestDispatcher_Apply_EngineError(t *testing.T) {
	d := New(Deps{Engine: &fakeEngine{applyErr: errors.New("nope")}, Logger: slog.Default()})
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "1", Kind: controlplane.CommandApply, ContainerID: "c1"})
	if ack.Success {
		t.Fatal("expected failure")
	}
}

func TestDispatcher_Disable_Success(t *testing.T) {
	d := New(Deps{Engine: &fakeEngine{}, Logger: slog.Default()})
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "1", Kind: controlplane.CommandDisable, ContainerID: "c1"})
	if !ack.Success {
		t.Fatalf("expected success: %s", ack.Error)
	}
}

func TestDispatcher_Reconcile_Success(t *testing.T) {
	d := New(Deps{Engine: &fakeEngine{}, Logger: slog.Default()})
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "1", Kind: controlplane.CommandReconcile})
	if !ack.Success {
		t.Fatalf("expected success: %s", ack.Error)
	}
}

func TestAutogenLabelsSnippet(t *testing.T) {
	p := autogen.Proposal{ContainerID: "abc", Ports: []uint16{80, 443}, Peers: []string{"10.0.0.0/8"}}
	got := autogenLabelsSnippet(p)
	if !strings.Contains(got, "firefik.enable") || !strings.Contains(got, "80,443") || !strings.Contains(got, "10.0.0.0/8") {
		t.Errorf("snippet: %s", got)
	}
}

func TestAutogenPolicySnippet(t *testing.T) {
	p := autogen.Proposal{ContainerID: "abc", Ports: []uint16{80}, Peers: []string{"10.0.0.0/8"}}
	got := autogenPolicySnippet(p)
	if !strings.Contains(got, "policy \"abc\"") || !strings.Contains(got, "allow tcp dport 80") || !strings.Contains(got, "10.0.0.0/8") {
		t.Errorf("snippet: %s", got)
	}
}

func TestProposalSource(t *testing.T) {
	obs := autogen.NewObserver()
	cfg := &config.Config{AutogenMinSamples: 1}
	a := &ProposalSource{Observer: obs, Config: cfg}
	got := a.Proposals(context.Background())
	if got == nil {
		got = []controlplane.AutogenProposal{}
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %d", len(got))
	}

	nilA := &ProposalSource{}
	if r := nilA.Proposals(context.Background()); r != nil {
		t.Errorf("nil observer should yield nil, got %+v", r)
	}
}
