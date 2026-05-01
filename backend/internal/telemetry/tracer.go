package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const tracerName = "firefik"

type Shutdown func(context.Context) error

func Init(ctx context.Context, version string, logger *slog.Logger) (Shutdown, error) {
	if !enabled() {
		otel.SetTracerProvider(noop.NewTracerProvider())
		return func(context.Context) error { return nil }, nil
	}

	ratio, ratioRaw, valid := validateSampleRatio()
	if !valid {
		logger.Warn("invalid FIREFIK_OTEL_SAMPLE_RATIO, falling back to 1.0",
			"got", ratioRaw)
	}

	proto := protocol()
	ep := endpointForProtocol(proto)

	exporter, err := newExporter(ctx, proto, ep)
	if err != nil {
		return nil, fmt.Errorf("otel: build exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(serviceName()),
		semconv.ServiceVersion(version),
	))
	if err != nil {
		_ = exporter.Shutdown(ctx)
		return nil, fmt.Errorf("otel: build resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	logger.Info("opentelemetry enabled",
		"endpoint", ep,
		"protocol", proto,
		"sample_ratio", ratio,
	)

	return tp.Shutdown, nil
}

func Tracer() trace.Tracer {
	return otel.GetTracerProvider().Tracer(tracerName)
}

func enabled() bool {
	switch os.Getenv("FIREFIK_OTEL_ENABLED") {
	case "true", "1", "yes":
		return true
	}
	return false
}

func endpoint() string {
	return endpointForProtocol(protocol())
}

func endpointForProtocol(proto string) string {
	if v := os.Getenv("FIREFIK_OTEL_ENDPOINT"); v != "" {
		return v
	}
	switch proto {
	case "http", "http/protobuf":
		return "localhost:4318"
	default:
		return "localhost:4317"
	}
}

func serviceName() string {
	if v := os.Getenv("FIREFIK_OTEL_SERVICE_NAME"); v != "" {
		return v
	}
	return "firefik"
}

func protocol() string {
	if v := os.Getenv("FIREFIK_OTEL_PROTOCOL"); v != "" {
		return v
	}
	return "grpc"
}

func sampleRatio() float64 {
	r, _, _ := validateSampleRatio()
	return r
}

func validateSampleRatio() (ratio float64, raw string, valid bool) {
	raw = os.Getenv("FIREFIK_OTEL_SAMPLE_RATIO")
	if raw == "" {
		return 1.0, "", true
	}
	if f, err := strconv.ParseFloat(raw, 64); err == nil && f >= 0 && f <= 1 {
		return f, raw, true
	}
	return 1.0, raw, false
}

func newExporter(ctx context.Context, proto, ep string) (sdktrace.SpanExporter, error) {
	switch proto {
	case "http", "http/protobuf":
		return otlptrace.New(ctx, otlptracehttp.NewClient(
			otlptracehttp.WithEndpoint(ep),
			otlptracehttp.WithInsecure(),
		))
	default:
		return otlptrace.New(ctx, otlptracegrpc.NewClient(
			otlptracegrpc.WithEndpoint(ep),
			otlptracegrpc.WithInsecure(),
		))
	}
}
