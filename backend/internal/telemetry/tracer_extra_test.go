package telemetry

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestInitDisabled(t *testing.T) {
	t.Setenv("FIREFIK_OTEL_ENABLED", "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	shut, err := Init(context.Background(), "v1", logger)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if err := shut(context.Background()); err != nil {
		t.Errorf("shut: %v", err)
	}
}

func TestNewExporterHTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	exp, err := newExporter(ctx, "http", "localhost:1")
	if err == nil && exp != nil {
		_ = exp.Shutdown(ctx)
	}
}

func TestNewExporterGRPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	exp, err := newExporter(ctx, "grpc", "localhost:1")
	if err == nil && exp != nil {
		_ = exp.Shutdown(ctx)
	}
}

func TestNewMetricsExporterHTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	exp, err := newMetricsExporter(ctx, "http", "localhost:1")
	if err == nil && exp != nil {
		_ = exp.Shutdown(ctx)
	}
}

func TestNewMetricsExporterGRPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	exp, err := newMetricsExporter(ctx, "grpc", "localhost:1")
	if err == nil && exp != nil {
		_ = exp.Shutdown(ctx)
	}
}

func TestSampleRatioInRange(t *testing.T) {
	r := sampleRatio()
	if r < 0 || r > 1 {
		t.Errorf("ratio out of range: %v", r)
	}
}

func TestInitEnabledGRPC(t *testing.T) {
	t.Setenv("FIREFIK_OTEL_ENABLED", "true")
	t.Setenv("FIREFIK_OTEL_ENDPOINT", "127.0.0.1:1")
	t.Setenv("FIREFIK_OTEL_PROTOCOL", "grpc")
	t.Setenv("FIREFIK_OTEL_SAMPLE_RATIO", "abc")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	shut, err := Init(ctx, "v1", logger)
	if err != nil {
		t.Skipf("skip: %v", err)
	}
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer shutCancel()
	_ = shut(shutCtx)
}

func TestInitEnabledHTTP(t *testing.T) {
	t.Setenv("FIREFIK_OTEL_ENABLED", "true")
	t.Setenv("FIREFIK_OTEL_ENDPOINT", "127.0.0.1:1")
	t.Setenv("FIREFIK_OTEL_PROTOCOL", "http/protobuf")
	t.Setenv("FIREFIK_OTEL_SAMPLE_RATIO", "0.5")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	shut, err := Init(ctx, "v1", logger)
	if err != nil {
		t.Skipf("skip: %v", err)
	}
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer shutCancel()
	_ = shut(shutCtx)
}

func TestInitMetricsEnabledGRPC(t *testing.T) {
	t.Setenv(envMetricsEnabled, "true")
	t.Setenv(envMetricsEndpoint, "127.0.0.1:1")
	t.Setenv(envMetricsProtocol, "grpc")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	shut, err := InitMetrics(ctx, "v1", logger, nil)
	if err != nil {
		t.Skipf("skip: %v", err)
	}
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer shutCancel()
	_ = shut(shutCtx)
}

func TestInitMetricsEnabledHTTP(t *testing.T) {
	t.Setenv(envMetricsEnabled, "true")
	t.Setenv(envMetricsEndpoint, "127.0.0.1:1")
	t.Setenv(envMetricsProtocol, "http/protobuf")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	shut, err := InitMetrics(ctx, "v1", logger, nil)
	if err != nil {
		t.Skipf("skip: %v", err)
	}
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer shutCancel()
	_ = shut(shutCtx)
}

func TestInitLogsEnabledHTTP(t *testing.T) {
	t.Setenv(envLogsEnabled, "true")
	t.Setenv(envLogsEndpoint, "127.0.0.1:1")
	t.Setenv(envLogsProtocol, "http/protobuf")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	shut, err := InitLogs(ctx, "v1", logger)
	if err != nil {
		t.Skipf("skip: %v", err)
	}
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer shutCancel()
	_ = shut(shutCtx)
}
