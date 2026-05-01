package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/log/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

const (
	envLogsEnabled  = "FIREFIK_OTEL_LOGS_ENABLED"
	envLogsEndpoint = "FIREFIK_OTEL_LOGS_ENDPOINT"
	envLogsProtocol = "FIREFIK_OTEL_LOGS_PROTOCOL"
	envLogsTimeout  = "FIREFIK_OTEL_LOGS_TIMEOUT"
	defaultLogsHTTP = "localhost:4318"
	defaultLogsGRPC = "localhost:4317"
	logScopeName    = "firefik"
)

func InitLogs(ctx context.Context, version string, logger *slog.Logger) (Shutdown, error) {
	if !logsEnabled() {
		global.SetLoggerProvider(noop.NewLoggerProvider())
		return func(context.Context) error { return nil }, nil
	}

	proto := logsProtocol()
	ep := logsEndpoint(proto)

	exporter, err := newLogsExporter(ctx, proto, ep)
	if err != nil {
		return nil, fmt.Errorf("otel logs: build exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(serviceName()),
		semconv.ServiceVersion(version),
	))
	if err != nil {
		_ = exporter.Shutdown(ctx)
		return nil, fmt.Errorf("otel logs: build resource: %w", err)
	}

	processor := sdklog.NewBatchProcessor(exporter,
		sdklog.WithExportTimeout(logsTimeout()),
	)
	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(processor),
	)
	global.SetLoggerProvider(provider)

	logger.Info("opentelemetry logs enabled",
		"endpoint", ep,
		"protocol", proto,
	)
	return provider.Shutdown, nil
}

func Logger() log.Logger {
	return global.GetLoggerProvider().Logger(logScopeName)
}

func logsEnabled() bool {
	switch strings.ToLower(os.Getenv(envLogsEnabled)) {
	case "true", "1", "yes":
		return true
	}
	return false
}

func LogsEnabledFromEnv() bool { return logsEnabled() }

func logsProtocol() string {
	if v := os.Getenv(envLogsProtocol); v != "" {
		return v
	}
	return "grpc"
}

func logsEndpoint(proto string) string {
	if v := os.Getenv(envLogsEndpoint); v != "" {
		return v
	}
	switch proto {
	case "http", "http/protobuf":
		return defaultLogsHTTP
	default:
		return defaultLogsGRPC
	}
}

func logsTimeout() time.Duration {
	if v := os.Getenv(envLogsTimeout); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Second {
			return d
		}
	}
	return 30 * time.Second
}

func newLogsExporter(ctx context.Context, proto, ep string) (sdklog.Exporter, error) {
	switch proto {
	case "http", "http/protobuf":
		return otlploghttp.New(ctx,
			otlploghttp.WithEndpoint(ep),
			otlploghttp.WithInsecure(),
		)
	default:
		return otlploggrpc.New(ctx,
			otlploggrpc.WithEndpoint(ep),
			otlploggrpc.WithInsecure(),
		)
	}
}
