package rules

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"firefik/internal/audit"
	"firefik/internal/config"
	"firefik/internal/docker"
)

func installRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})
	return recorder
}

func findAttr(attrs []attribute.KeyValue, key string) (attribute.Value, bool) {
	for _, kv := range attrs {
		if string(kv.Key) == key {
			return kv.Value, true
		}
	}
	return attribute.Value{}, false
}

type fakeBackend struct {
	containerIDs []string
	removeErr    error
	applyErr     error
}

func (f *fakeBackend) SetupChains() error { return nil }
func (f *fakeBackend) Cleanup() error     { return nil }
func (f *fakeBackend) ApplyContainerRules(string, string, []net.IP, []docker.FirewallRuleSet, string, []net.IPNet) error {
	return f.applyErr
}
func (f *fakeBackend) RemoveContainerChains(string) error         { return f.removeErr }
func (f *fakeBackend) ListAppliedContainerIDs() ([]string, error) { return f.containerIDs, nil }
func (f *fakeBackend) Healthy() (HealthReport, error)             { return HealthReport{}, nil }

type fakeDocker struct {
	containers []docker.ContainerInfo
	listErr    error
}

func (f *fakeDocker) ListContainers(ctx context.Context) ([]docker.ContainerInfo, error) {
	return f.containers, f.listErr
}

func (f *fakeDocker) Inspect(ctx context.Context, id string) (docker.ContainerInfo, bool, error) {
	for _, c := range f.containers {
		if c.ID == id {
			return c, true, nil
		}
	}
	return docker.ContainerInfo{}, false, nil
}

func newTestEngine(back Backend, doc DockerReader) *Engine {
	cfg := &config.Config{
		ChainName:      "FIREFIK",
		EffectiveChain: "FIREFIK",
		DefaultPolicy:  "RETURN",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewEngine(back, doc, cfg, logger)
}

func TestRehydrateSpan(t *testing.T) {
	recorder := installRecorder(t)
	eng := newTestEngine(&fakeBackend{containerIDs: []string{"abc123", "def456"}}, &fakeDocker{})

	if err := eng.Rehydrate(context.Background()); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	s := spans[0]
	if s.Name() != "engine.Rehydrate" {
		t.Errorf("span name = %q", s.Name())
	}
	if v, ok := findAttr(s.Attributes(), "firefik.rehydrated_count"); !ok || v.AsInt64() != 2 {
		t.Errorf("firefik.rehydrated_count = %v ok=%v", v.AsInt64(), ok)
	}
	if s.Status().Code == codes.Error {
		t.Errorf("unexpected error status: %v", s.Status())
	}
}

func TestReconcileSpanSource(t *testing.T) {
	recorder := installRecorder(t)
	eng := newTestEngine(&fakeBackend{}, &fakeDocker{containers: nil})

	if err := eng.Reconcile(context.Background(), audit.SourceStartup); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	spans := recorder.Ended()
	var reconcile sdktrace.ReadOnlySpan
	for i := range spans {
		if spans[i].Name() == "engine.Reconcile" {
			reconcile = spans[i]
			break
		}
	}
	if reconcile == nil {
		t.Fatalf("no engine.Reconcile span found in %d recorded", len(spans))
	}
	v, ok := findAttr(reconcile.Attributes(), "firefik.source")
	if !ok {
		t.Fatal("firefik.source attribute missing")
	}
	if v.AsString() != string(audit.SourceStartup) {
		t.Errorf("firefik.source = %q, want %q", v.AsString(), audit.SourceStartup)
	}
}

func TestReconcileDefaultsSourceWhenEmpty(t *testing.T) {
	recorder := installRecorder(t)
	eng := newTestEngine(&fakeBackend{}, &fakeDocker{})

	if err := eng.Reconcile(context.Background(), ""); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	spans := recorder.Ended()
	if len(spans) == 0 {
		t.Fatal("no spans recorded")
	}
	for _, s := range spans {
		if s.Name() != "engine.Reconcile" {
			continue
		}
		v, ok := findAttr(s.Attributes(), "firefik.source")
		if !ok || v.AsString() != string(audit.SourceConfigReload) {
			t.Errorf("default source = %v (ok=%v), want %q", v.AsString(), ok, audit.SourceConfigReload)
		}
	}
}

func TestReconcileSpanOnError(t *testing.T) {
	recorder := installRecorder(t)
	eng := newTestEngine(&fakeBackend{}, &fakeDocker{listErr: errors.New("daemon down")})

	_ = eng.Reconcile(context.Background(), audit.SourceStartup)

	for _, s := range recorder.Ended() {
		if s.Name() != "engine.Reconcile" {
			continue
		}
		if s.Status().Code != codes.Error {
			t.Errorf("span status = %v, want error", s.Status())
		}
		return
	}
	t.Fatal("engine.Reconcile span not found")
}

func TestApplyContainerSpanAttributes(t *testing.T) {
	recorder := installRecorder(t)
	eng := newTestEngine(&fakeBackend{}, &fakeDocker{})

	_ = eng.ApplyContainer(context.Background(), "deadbeef1234", audit.SourceEvent)

	for _, s := range recorder.Ended() {
		if s.Name() != "engine.ApplyContainer" {
			continue
		}
		cid, ok := findAttr(s.Attributes(), "container.id")
		if !ok || cid.AsString() != "deadbeef1234" {
			t.Errorf("container.id = %v ok=%v", cid.AsString(), ok)
		}
		src, ok := findAttr(s.Attributes(), "audit.source")
		if !ok || src.AsString() != string(audit.SourceEvent) {
			t.Errorf("audit.source = %v ok=%v", src.AsString(), ok)
		}
		return
	}
	t.Fatal("engine.ApplyContainer span not found")
}
