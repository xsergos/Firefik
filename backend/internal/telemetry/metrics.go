package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

const (
	envMetricsEnabled  = "FIREFIK_OTEL_METRICS_ENABLED"
	envMetricsEndpoint = "FIREFIK_OTEL_METRICS_ENDPOINT"
	envMetricsProtocol = "FIREFIK_OTEL_METRICS_PROTOCOL"
	envMetricsInterval = "FIREFIK_OTEL_METRICS_INTERVAL"
	defaultMetricsHTTP = "localhost:4318"
	defaultMetricsGRPC = "localhost:4317"
	bridgeScopeName    = "firefik/prometheus-bridge"
)

func InitMetrics(ctx context.Context, version string, logger *slog.Logger, gatherer prometheus.Gatherer) (Shutdown, error) {
	if !metricsEnabled() {
		otel.SetMeterProvider(noopmetric.NewMeterProvider())
		return func(context.Context) error { return nil }, nil
	}
	if gatherer == nil {
		gatherer = prometheus.DefaultGatherer
	}

	proto := metricsProtocol()
	ep := metricsEndpoint(proto)
	interval := metricsInterval()

	exporter, err := newMetricsExporter(ctx, proto, ep)
	if err != nil {
		return nil, fmt.Errorf("otel metrics: build exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(serviceName()),
		semconv.ServiceVersion(version),
	))
	if err != nil {
		_ = exporter.Shutdown(ctx)
		return nil, fmt.Errorf("otel metrics: build resource: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(
		exporter,
		sdkmetric.WithInterval(interval),
		sdkmetric.WithProducer(&prometheusBridge{gatherer: gatherer}),
	)

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	)
	otel.SetMeterProvider(provider)

	logger.Info("opentelemetry metrics enabled",
		"endpoint", ep,
		"protocol", proto,
		"interval", interval,
	)
	return provider.Shutdown, nil
}

func metricsEnabled() bool {
	switch strings.ToLower(os.Getenv(envMetricsEnabled)) {
	case "true", "1", "yes":
		return true
	}
	return false
}

func metricsProtocol() string {
	if v := os.Getenv(envMetricsProtocol); v != "" {
		return v
	}
	return "grpc"
}

func metricsEndpoint(proto string) string {
	if v := os.Getenv(envMetricsEndpoint); v != "" {
		return v
	}
	switch proto {
	case "http", "http/protobuf":
		return defaultMetricsHTTP
	default:
		return defaultMetricsGRPC
	}
}

func metricsInterval() time.Duration {
	if v := os.Getenv(envMetricsInterval); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Second {
			return d
		}
	}
	return 30 * time.Second
}

func newMetricsExporter(ctx context.Context, proto, ep string) (sdkmetric.Exporter, error) {
	switch proto {
	case "http", "http/protobuf":
		return otlpmetrichttp.New(ctx,
			otlpmetrichttp.WithEndpoint(ep),
			otlpmetrichttp.WithInsecure(),
		)
	default:
		return otlpmetricgrpc.New(ctx,
			otlpmetricgrpc.WithEndpoint(ep),
			otlpmetricgrpc.WithInsecure(),
		)
	}
}

type prometheusBridge struct {
	gatherer  prometheus.Gatherer
	startTime time.Time
}

func (p *prometheusBridge) Produce(_ context.Context) ([]metricdata.ScopeMetrics, error) {
	families, err := p.gatherer.Gather()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if p.startTime.IsZero() {
		p.startTime = now
	}
	out := make([]metricdata.Metrics, 0, len(families))
	for _, fam := range families {
		converted, ok := convertFamily(fam, p.startTime, now)
		if !ok {
			continue
		}
		out = append(out, converted)
	}
	return []metricdata.ScopeMetrics{{
		Scope:   instrumentation.Scope{Name: bridgeScopeName},
		Metrics: out,
	}}, nil
}

func convertFamily(fam *dto.MetricFamily, startTime, now time.Time) (metricdata.Metrics, bool) {
	if fam == nil || fam.Name == nil {
		return metricdata.Metrics{}, false
	}
	m := metricdata.Metrics{
		Name:        fam.GetName(),
		Description: fam.GetHelp(),
	}
	switch fam.GetType() {
	case dto.MetricType_COUNTER:
		points := make([]metricdata.DataPoint[float64], 0, len(fam.Metric))
		for _, mm := range fam.Metric {
			if mm.Counter == nil {
				continue
			}
			points = append(points, metricdata.DataPoint[float64]{
				Attributes: attrsFromLabels(mm.Label),
				StartTime:  startTime,
				Time:       now,
				Value:      mm.Counter.GetValue(),
			})
		}
		m.Data = metricdata.Sum[float64]{
			DataPoints:  points,
			Temporality: metricdata.CumulativeTemporality,
			IsMonotonic: true,
		}
	case dto.MetricType_GAUGE:
		points := make([]metricdata.DataPoint[float64], 0, len(fam.Metric))
		for _, mm := range fam.Metric {
			if mm.Gauge == nil {
				continue
			}
			points = append(points, metricdata.DataPoint[float64]{
				Attributes: attrsFromLabels(mm.Label),
				StartTime:  startTime,
				Time:       now,
				Value:      mm.Gauge.GetValue(),
			})
		}
		m.Data = metricdata.Gauge[float64]{DataPoints: points}
	case dto.MetricType_HISTOGRAM:
		points := make([]metricdata.HistogramDataPoint[float64], 0, len(fam.Metric))
		for _, mm := range fam.Metric {
			if mm.Histogram == nil {
				continue
			}
			bounds := make([]float64, 0, len(mm.Histogram.Bucket))
			counts := make([]uint64, 0, len(mm.Histogram.Bucket)+1)
			var prev uint64
			for _, b := range mm.Histogram.Bucket {
				if b == nil {
					continue
				}
				upper := b.GetUpperBound()
				bounds = append(bounds, upper)
				cur := b.GetCumulativeCount()
				counts = append(counts, cur-prev)
				prev = cur
			}
			counts = append(counts, mm.Histogram.GetSampleCount()-prev)
			sum := mm.Histogram.GetSampleSum()
			points = append(points, metricdata.HistogramDataPoint[float64]{
				Attributes:   attrsFromLabels(mm.Label),
				StartTime:    startTime,
				Time:         now,
				Count:        mm.Histogram.GetSampleCount(),
				Bounds:       bounds,
				BucketCounts: counts,
				Sum:          sum,
			})
		}
		m.Data = metricdata.Histogram[float64]{
			DataPoints:  points,
			Temporality: metricdata.CumulativeTemporality,
		}
	default:
		return metricdata.Metrics{}, false
	}
	return m, true
}

func attrsFromLabels(labels []*dto.LabelPair) attribute.Set {
	if len(labels) == 0 {
		return *attribute.EmptySet()
	}
	kv := make([]attribute.KeyValue, 0, len(labels))
	for _, l := range labels {
		if l == nil {
			continue
		}
		kv = append(kv, attribute.String(l.GetName(), l.GetValue()))
	}
	return attribute.NewSet(kv...)
}

var (
	errBridgeStopped = errors.New("prometheus bridge stopped")
	_                = errBridgeStopped
	_                = strconv.Itoa
)
