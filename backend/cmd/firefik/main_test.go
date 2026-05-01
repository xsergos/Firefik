package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"firefik/internal/audit"
	"firefik/internal/config"
	"firefik/internal/controlplane"
	"firefik/internal/docker"
	"firefik/internal/rules"
)

func TestFirstNonEmpty(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"", "", "x"}, "x"},
		{[]string{"a", "b"}, "a"},
		{[]string{"", ""}, ""},
	}
	for _, c := range cases {
		if got := firstNonEmpty(c.in...); got != c.want {
			t.Errorf("firstNonEmpty(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSplitAndTrim(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a, b ,c", []string{"a", "b", "c"}},
		{"  ,  ", []string{"", ""}},
	}
	for _, c := range cases {
		got := splitAndTrim(c.in)
		if len(got) != len(c.want) {
			t.Errorf("splitAndTrim(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitAndTrim(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestBuildSingleSinkNone(t *testing.T) {
	for _, kind := range []string{"", "none"} {
		s, err := buildSingleSink(kind, "", "v", audit.RotationConfig{}, audit.RemoteSinkOptions{}, nil)
		if err != nil || s != nil {
			t.Errorf("kind %q: got s=%v err=%v", kind, s, err)
		}
	}
}

func TestBuildSingleSinkJSON(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := buildSingleSink("json-file", tmp, "v", audit.RotationConfig{}, audit.RemoteSinkOptions{}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if s == nil {
		t.Fatal("expected sink")
	}
	_ = s.Close()
}

func TestBuildSingleSinkCEF(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "audit.cef")
	s, err := buildSingleSink("cef", tmp, "v", audit.RotationConfig{}, audit.RemoteSinkOptions{}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	_ = s.Close()
}

func TestBuildSingleSinkRemoteMissingEndpoint(t *testing.T) {
	if _, err := buildSingleSink("remote", "", "v", audit.RotationConfig{}, audit.RemoteSinkOptions{}, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildSingleSinkHistoryNil(t *testing.T) {
	if _, err := buildSingleSink("history", "", "v", audit.RotationConfig{}, audit.RemoteSinkOptions{}, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildSingleSinkHistory(t *testing.T) {
	hb := audit.NewHistoryBuffer(10)
	s, err := buildSingleSink("history", "", "v", audit.RotationConfig{}, audit.RemoteSinkOptions{}, hb)
	if err != nil || s == nil {
		t.Errorf("err=%v s=%v", err, s)
	}
}

func TestBuildSingleSinkUnknown(t *testing.T) {
	if _, err := buildSingleSink("voodoo", "", "v", audit.RotationConfig{}, audit.RemoteSinkOptions{}, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildConfiguredSinksEmpty(t *testing.T) {
	cfg := &config.Config{AuditSinkType: ""}
	got, err := buildConfiguredSinks(cfg, slog.Default(), "v", nil)
	if err != nil || got != nil {
		t.Errorf("got %v %v", got, err)
	}

	cfg.AuditSinkType = "none"
	got, err = buildConfiguredSinks(cfg, slog.Default(), "v", nil)
	if err != nil || got != nil {
		t.Errorf("none: got %v %v", got, err)
	}
}

func TestBuildConfiguredSinksSingle(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "a.jsonl")
	cfg := &config.Config{AuditSinkType: "json-file", AuditSinkPath: tmp}
	got, err := buildConfiguredSinks(cfg, slog.Default(), "v", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 sink, got %d", len(got))
	}
	_ = got[0].Close()
}

func TestBuildConfiguredSinksSingleError(t *testing.T) {
	cfg := &config.Config{AuditSinkType: "voodoo"}
	if _, err := buildConfiguredSinks(cfg, slog.Default(), "v", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildConfiguredSinksMultiPathMismatch(t *testing.T) {
	cfg := &config.Config{AuditSinkType: "json-file,cef-file", AuditSinkPath: ""}
	if _, err := buildConfiguredSinks(cfg, slog.Default(), "v", nil); err == nil {
		t.Fatal("expected error")
	}

	cfg.AuditSinkPath = "only-one"
	if _, err := buildConfiguredSinks(cfg, slog.Default(), "v", nil); err == nil {
		t.Fatal("expected error mismatch")
	}
}

func TestBuildConfiguredSinksMulti(t *testing.T) {
	d := t.TempDir()
	p1 := filepath.Join(d, "a.jsonl")
	p2 := filepath.Join(d, "b.cef")
	cfg := &config.Config{AuditSinkType: "json-file,cef-file", AuditSinkPath: p1 + "," + p2}
	got, err := buildConfiguredSinks(cfg, slog.Default(), "v", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 sinks, got %d", len(got))
	}
	for _, s := range got {
		_ = s.Close()
	}
}

func TestBuildConfiguredSinksMultiBadKind(t *testing.T) {
	cfg := &config.Config{AuditSinkType: "json-file,voodoo", AuditSinkPath: "a,b"}
	if _, err := buildConfiguredSinks(cfg, slog.Default(), "v", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildAuditSinkNone(t *testing.T) {
	cfg := &config.Config{}
	s, err := buildAuditSink(cfg, slog.Default(), "v", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if s != nil {
		t.Errorf("expected nil")
	}
}

func TestBuildAuditSinkSingle(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "a.jsonl")
	cfg := &config.Config{AuditSinkType: "json-file", AuditSinkPath: tmp}
	s, err := buildAuditSink(cfg, slog.Default(), "v", nil)
	if err != nil || s == nil {
		t.Fatalf("err=%v s=%v", err, s)
	}
	_ = s.Close()
}

func TestBuildAuditSinkMulti(t *testing.T) {
	d := t.TempDir()
	cfg := &config.Config{
		AuditSinkType: "json-file,cef-file",
		AuditSinkPath: filepath.Join(d, "a.jsonl") + "," + filepath.Join(d, "b.cef"),
	}
	s, err := buildAuditSink(cfg, slog.Default(), "v", nil)
	if err != nil || s == nil {
		t.Fatalf("err=%v s=%v", err, s)
	}
	_ = s.Close()
}

func TestBuildAuditSinkConfigError(t *testing.T) {
	cfg := &config.Config{AuditSinkType: "remote"}
	if _, err := buildAuditSink(cfg, slog.Default(), "v", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildWebhookSinkEmptyURL(t *testing.T) {
	cfg := &config.Config{}
	if got := buildWebhookSink(cfg, slog.Default()); got != nil {
		t.Errorf("expected nil")
	}
}

func TestBuildWebhookSinkValid(t *testing.T) {
	cfg := &config.Config{WebhookURL: "https://example.com/hook", WebhookEvents: []string{"apply"}, WebhookTimeoutMS: 100}
	if got := buildWebhookSink(cfg, slog.Default()); got == nil {
		t.Errorf("expected non-nil")
	}
}

func TestBuildAuditSinkWebhookOnly(t *testing.T) {
	cfg := &config.Config{WebhookURL: "https://example.com/hook"}
	s, err := buildAuditSink(cfg, slog.Default(), "v", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if s == nil {
		t.Errorf("expected sink")
	}
}

func TestSelectBackendOnNonLinux(t *testing.T) {
	cfg := &config.Config{Backend: "iptables", ChainName: "FIREFIK", ParentChain: "DOCKER-USER"}
	if _, err := selectBackend(cfg, slog.Default()); err == nil {
		t.Skip("backend select succeeded — likely on Linux with iptables available")
	}
}

func TestSelectBackendNftablesNonLinux(t *testing.T) {
	cfg := &config.Config{Backend: "nftables", ChainName: "FIREFIK"}
	if _, err := selectBackend(cfg, slog.Default()); err == nil {
		t.Skip("backend select succeeded — likely on Linux with nftables available")
	}
}

func TestEngineDispatcherUnknown(t *testing.T) {
	d := &engineDispatcher{logger: slog.Default()}
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "1", Kind: "voodoo"})
	if ack.Success {
		t.Errorf("expected failure")
	}
	if ack.Error == "" {
		t.Errorf("expected error")
	}
}

func TestEngineDispatcherApplyMissingContainer(t *testing.T) {
	d := &engineDispatcher{logger: slog.Default()}
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "1", Kind: controlplane.CommandApply})
	if ack.Success {
		t.Errorf("expected failure")
	}
}

func TestEngineDispatcherDisableMissingContainer(t *testing.T) {
	d := &engineDispatcher{logger: slog.Default()}
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "1", Kind: controlplane.CommandDisable})
	if ack.Success {
		t.Errorf("expected failure")
	}
}

func TestEngineDispatcherTokenRotateRejected(t *testing.T) {
	d := &engineDispatcher{logger: slog.Default()}
	ack := d.Dispatch(context.Background(), controlplane.Command{ID: "x", Kind: controlplane.CommandTokenRotate})
	if ack.Success {
		t.Errorf("token-rotate is operator-driven, should be rejected via control plane")
	}
	if ack.Error == "" {
		t.Errorf("expected an error message explaining why token-rotate is rejected")
	}
}

func TestEngineDispatcherApplyAndDisableNoEngine(t *testing.T) {
	d := &engineDispatcher{logger: slog.Default()}
	defer func() { _ = recover() }()
	d.Dispatch(context.Background(), controlplane.Command{ID: "1", Kind: controlplane.CommandApply, ContainerID: "abc"})
}

func TestEngineDispatcherReconcileNoEngine(t *testing.T) {
	d := &engineDispatcher{logger: slog.Default()}
	defer func() { _ = recover() }()
	d.Dispatch(context.Background(), controlplane.Command{ID: "1", Kind: controlplane.CommandReconcile})
}

func TestRunBadChainSuffix(t *testing.T) {
	t.Setenv("FIREFIK_CHAIN_NAME", "FIREFIK")
	t.Setenv("FIREFIK_CHAIN_SUFFIX", "bad space")
	t.Setenv("FIREFIK_BACKEND", "iptables")
	t.Setenv("FIREFIK_OTEL_ENABLED", "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run(logger); err == nil {
		t.Errorf("expected error")
	}
}

func TestCleanupOldSuffixesNoop(t *testing.T) {
	cfg := &config.Config{}
	if err := cleanupOldSuffixes(cfg, slog.Default(), nil); err != nil {
		t.Errorf("expected nil: %v", err)
	}
}

func TestCleanupOldSuffixesNoLegacy(t *testing.T) {
	cfg := &config.Config{
		ChainName:          "FIREFIK",
		EffectiveChain:     "FIREFIK",
		CleanupOldSuffixes: []string{"v0"},
	}
	_ = cleanupOldSuffixes(cfg, slog.Default(), nil)
}

func TestCleanupOldSuffixesWithAuditLog(t *testing.T) {
	cfg := &config.Config{
		ChainName:          "FIREFIK",
		EffectiveChain:     "FIREFIK-v2",
		CleanupOldSuffixes: []string{"v0", "v1"},
		Backend:            "iptables",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditLog := audit.New(logger)
	_ = cleanupOldSuffixes(cfg, logger, auditLog)
}

var _ = errors.New

func TestSetupTracesDisabled(t *testing.T) {
	t.Setenv("FIREFIK_OTEL_ENABLED", "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sh := setupTraces(logger, "v1")
	if sh == nil {
		t.Errorf("expected non-nil noop shutdown when disabled")
	}
	runShutdown(logger, "trace shutdown failed", sh)
}

func TestSetupMetricsDisabled(t *testing.T) {
	t.Setenv("FIREFIK_OTEL_METRICS_ENABLED", "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sh := setupMetrics(logger, "v1")
	if sh == nil {
		t.Errorf("expected non-nil noop shutdown when disabled")
	}
	runShutdown(logger, "metrics shutdown failed", sh)
}

func TestSetupLogsDisabled(t *testing.T) {
	t.Setenv("FIREFIK_OTEL_LOGS_ENABLED", "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sh := setupLogs(logger, "v1")
	if sh == nil {
		t.Errorf("expected non-nil noop shutdown when disabled")
	}
	runShutdown(logger, "logs shutdown failed", sh)
}

func TestRunShutdownNilNoop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runShutdown(logger, "x", nil)
}

type fakeDockerReader struct {
	containers []dockerContainer
	listErr    error
}

type dockerContainer struct {
	id     string
	name   string
	status string
	labels map[string]string
}

func (f *fakeDockerReader) ListContainers(ctx context.Context) ([]docker.ContainerInfo, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]docker.ContainerInfo, 0, len(f.containers))
	for _, c := range f.containers {
		out = append(out, docker.ContainerInfo{
			ID:     c.id,
			Name:   c.name,
			Status: c.status,
			Labels: c.labels,
		})
	}
	return out, nil
}

func (f *fakeDockerReader) Inspect(ctx context.Context, id string) (docker.ContainerInfo, bool, error) {
	for _, c := range f.containers {
		if c.id == id {
			return docker.ContainerInfo{ID: c.id, Name: c.name, Status: c.status, Labels: c.labels}, true, nil
		}
	}
	return docker.ContainerInfo{}, false, nil
}

func TestEngineSnapshotSourceListError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{ChainName: "FIREFIK", EffectiveChain: "FIREFIK", Backend: "iptables"}
	dr := &fakeDockerReader{listErr: errors.New("boom")}
	src := &engineSnapshotSource{
		engine: rules.NewEngine(nil, dr, cfg, logger),
		docker: dr,
	}
	_, err := src.Snapshot(context.Background(), controlplane.AgentIdentity{})
	if err == nil {
		t.Errorf("expected error from list failure")
	}
}

func TestEngineSnapshotSourceEmpty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{ChainName: "FIREFIK", EffectiveChain: "FIREFIK", Backend: "iptables"}
	dr := &fakeDockerReader{}
	src := &engineSnapshotSource{
		engine: rules.NewEngine(nil, dr, cfg, logger),
		docker: dr,
	}
	snap, err := src.Snapshot(context.Background(), controlplane.AgentIdentity{InstanceID: "host-a"})
	if err != nil {
		t.Errorf("snapshot: %v", err)
	}
	if snap.Agent.InstanceID != "host-a" {
		t.Errorf("agent identity not propagated: %+v", snap.Agent)
	}
	if len(snap.Containers) != 0 {
		t.Errorf("expected 0 containers, got %d", len(snap.Containers))
	}
	if snap.At.IsZero() {
		t.Errorf("snapshot timestamp is zero")
	}
}

func TestEngineSnapshotSourceWithContainers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{ChainName: "FIREFIK", EffectiveChain: "FIREFIK", Backend: "iptables"}
	dr := &fakeDockerReader{
		containers: []dockerContainer{
			{
				id:     "abcdef0123450000000000000000000000000000000000000000000000000000",
				name:   "web",
				status: "running",
				labels: map[string]string{"firefik.enable": "true"},
			},
		},
	}
	src := &engineSnapshotSource{
		engine: rules.NewEngine(nil, dr, cfg, logger),
		docker: dr,
	}
	snap, err := src.Snapshot(context.Background(), controlplane.AgentIdentity{InstanceID: "host-b"})
	if err != nil {
		t.Errorf("snapshot: %v", err)
	}
	if len(snap.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(snap.Containers))
	}
	c := snap.Containers[0]
	if c.Name != "web" || c.Status != "running" {
		t.Errorf("unexpected container: %+v", c)
	}
	if c.FirewallStatus != "disabled" {
		t.Errorf("expected disabled (no applied rules), got %q", c.FirewallStatus)
	}
}
