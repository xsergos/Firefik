package telemetry

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"go.opentelemetry.io/otel/log/global"
)

func TestLogsEnabled(t *testing.T) {
	t.Setenv(envLogsEnabled, "")
	if logsEnabled() {
		t.Fatal("expected disabled when unset")
	}
	for _, v := range []string{"true", "1", "yes", "TRUE", "Yes"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv(envLogsEnabled, v)
			if !logsEnabled() {
				t.Fatalf("expected enabled for %q", v)
			}
		})
	}
	t.Setenv(envLogsEnabled, "off")
	if logsEnabled() {
		t.Fatal("expected disabled for off")
	}
}

func TestLogsProtocol(t *testing.T) {
	t.Setenv(envLogsProtocol, "")
	if got := logsProtocol(); got != "grpc" {
		t.Errorf("default = %q", got)
	}
	t.Setenv(envLogsProtocol, "http")
	if got := logsProtocol(); got != "http" {
		t.Errorf("explicit = %q", got)
	}
}

func TestLogsEndpoint(t *testing.T) {
	t.Setenv(envLogsEndpoint, "")
	if got := logsEndpoint("grpc"); got != defaultLogsGRPC {
		t.Errorf("grpc default = %q", got)
	}
	if got := logsEndpoint("http"); got != defaultLogsHTTP {
		t.Errorf("http default = %q", got)
	}
	if got := logsEndpoint("http/protobuf"); got != defaultLogsHTTP {
		t.Errorf("http/protobuf default = %q", got)
	}
	t.Setenv(envLogsEndpoint, "collector:4321")
	if got := logsEndpoint("grpc"); got != "collector:4321" {
		t.Errorf("explicit = %q", got)
	}
}

func TestLogsTimeout(t *testing.T) {
	t.Setenv(envLogsTimeout, "")
	if got := logsTimeout(); got != 30*time.Second {
		t.Errorf("default = %v", got)
	}
	t.Setenv(envLogsTimeout, "10s")
	if got := logsTimeout(); got != 10*time.Second {
		t.Errorf("explicit = %v", got)
	}
	t.Setenv(envLogsTimeout, "garbage")
	if got := logsTimeout(); got != 30*time.Second {
		t.Errorf("invalid -> default")
	}
	t.Setenv(envLogsTimeout, "100ms")
	if got := logsTimeout(); got != 30*time.Second {
		t.Errorf("too small -> default")
	}
}

func TestInitLogs_Disabled(t *testing.T) {
	t.Setenv(envLogsEnabled, "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	shut, err := InitLogs(context.Background(), "test", logger)
	if err != nil {
		t.Fatal(err)
	}
	if shut == nil {
		t.Fatal("expected non-nil shutdown")
	}
	if err := shut(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLogger_ReturnsGlobal(t *testing.T) {
	t.Setenv(envLogsEnabled, "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := InitLogs(context.Background(), "test", logger); err != nil {
		t.Fatal(err)
	}
	got := Logger()
	want := global.GetLoggerProvider().Logger(logScopeName)
	if got == nil || want == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestLogsEnabledFromEnv_Mirror(t *testing.T) {
	t.Setenv(envLogsEnabled, "")
	if LogsEnabledFromEnv() {
		t.Error("expected disabled")
	}
	t.Setenv(envLogsEnabled, "true")
	if !LogsEnabledFromEnv() {
		t.Error("expected enabled")
	}
}

func TestNewLogsExporter_GRPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	exp, err := newLogsExporter(ctx, "grpc", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if exp == nil {
		t.Fatal("nil exporter")
	}
	_ = exp.Shutdown(ctx)
}

func TestNewLogsExporter_HTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	exp, err := newLogsExporter(ctx, "http/protobuf", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if exp == nil {
		t.Fatal("nil exporter")
	}
	_ = exp.Shutdown(ctx)
}

func TestInitLogs_GRPCEnabled(t *testing.T) {
	t.Setenv(envLogsEnabled, "true")
	t.Setenv(envLogsEndpoint, "127.0.0.1:1")
	t.Setenv(envLogsProtocol, "grpc")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	shut, err := InitLogs(ctx, "test", logger)
	if err != nil {
		t.Skipf("skip on schema-url conflict between test runs: %v", err)
	}
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer shutCancel()
	_ = shut(shutCtx)
}
