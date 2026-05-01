package telemetry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestMetricsEnabled(t *testing.T) {
	t.Setenv(envMetricsEnabled, "")
	if metricsEnabled() {
		t.Fatal("expected disabled when unset")
	}
	for _, v := range []string{"true", "1", "yes", "TRUE", "Yes"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv(envMetricsEnabled, v)
			if !metricsEnabled() {
				t.Fatalf("expected enabled for %q", v)
			}
		})
	}
	t.Setenv(envMetricsEnabled, "off")
	if metricsEnabled() {
		t.Fatal("expected disabled for off")
	}
}

func TestMetricsProtocol(t *testing.T) {
	t.Setenv(envMetricsProtocol, "")
	if got := metricsProtocol(); got != "grpc" {
		t.Errorf("default = %q, want grpc", got)
	}
	t.Setenv(envMetricsProtocol, "http")
	if got := metricsProtocol(); got != "http" {
		t.Errorf("explicit = %q", got)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	t.Setenv(envMetricsEndpoint, "")
	if got := metricsEndpoint("grpc"); got != defaultMetricsGRPC {
		t.Errorf("grpc default = %q", got)
	}
	if got := metricsEndpoint("http"); got != defaultMetricsHTTP {
		t.Errorf("http default = %q", got)
	}
	if got := metricsEndpoint("http/protobuf"); got != defaultMetricsHTTP {
		t.Errorf("http/protobuf default = %q", got)
	}
	t.Setenv(envMetricsEndpoint, "collector:9999")
	if got := metricsEndpoint("grpc"); got != "collector:9999" {
		t.Errorf("explicit = %q", got)
	}
}

func TestMetricsInterval(t *testing.T) {
	t.Setenv(envMetricsInterval, "")
	if got := metricsInterval(); got != 30*time.Second {
		t.Errorf("default = %v", got)
	}
	t.Setenv(envMetricsInterval, "10s")
	if got := metricsInterval(); got != 10*time.Second {
		t.Errorf("explicit = %v", got)
	}
	t.Setenv(envMetricsInterval, "garbage")
	if got := metricsInterval(); got != 30*time.Second {
		t.Errorf("invalid -> default, got %v", got)
	}
	t.Setenv(envMetricsInterval, "100ms")
	if got := metricsInterval(); got != 30*time.Second {
		t.Errorf("too small -> default, got %v", got)
	}
}

func TestInitMetrics_Disabled(t *testing.T) {
	t.Setenv(envMetricsEnabled, "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	shut, err := InitMetrics(context.Background(), "test", logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := shut(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPrometheusBridge_Counter(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_counter", Help: "h"})
	reg.MustRegister(c)
	c.Add(7)

	br := &prometheusBridge{gatherer: reg}
	scopes, err := br.Produce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 1 || len(scopes[0].Metrics) != 1 {
		t.Fatalf("unexpected shape: %+v", scopes)
	}
	m := scopes[0].Metrics[0]
	if m.Name != "test_counter" {
		t.Errorf("name = %q", m.Name)
	}
	sum, ok := m.Data.(metricdata.Sum[float64])
	if !ok {
		t.Fatalf("type = %T", m.Data)
	}
	if !sum.IsMonotonic {
		t.Error("expected monotonic")
	}
	if sum.Temporality != metricdata.CumulativeTemporality {
		t.Errorf("temporality = %v", sum.Temporality)
	}
	if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 7 {
		t.Errorf("data points: %+v", sum.DataPoints)
	}
}

func TestPrometheusBridge_GaugeAndLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_gauge", Help: "h"}, []string{"agent"})
	reg.MustRegister(g)
	g.WithLabelValues("a1").Set(42.5)
	g.WithLabelValues("a2").Set(11)

	br := &prometheusBridge{gatherer: reg}
	scopes, err := br.Produce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	gauge, ok := scopes[0].Metrics[0].Data.(metricdata.Gauge[float64])
	if !ok {
		t.Fatalf("type = %T", scopes[0].Metrics[0].Data)
	}
	if len(gauge.DataPoints) != 2 {
		t.Fatalf("points = %d", len(gauge.DataPoints))
	}
	for _, dp := range gauge.DataPoints {
		v, ok := dp.Attributes.Value("agent")
		if !ok {
			t.Errorf("missing agent attr")
		}
		switch v.AsString() {
		case "a1":
			if dp.Value != 42.5 {
				t.Errorf("a1 value = %v", dp.Value)
			}
		case "a2":
			if dp.Value != 11 {
				t.Errorf("a2 value = %v", dp.Value)
			}
		default:
			t.Errorf("unexpected label %q", v.AsString())
		}
	}
}

func TestPrometheusBridge_Histogram(t *testing.T) {
	reg := prometheus.NewRegistry()
	h := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "test_hist",
		Help:    "h",
		Buckets: []float64{1, 5, 10},
	})
	reg.MustRegister(h)
	h.Observe(0.5)
	h.Observe(3)
	h.Observe(20)

	br := &prometheusBridge{gatherer: reg}
	scopes, err := br.Produce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	hist, ok := scopes[0].Metrics[0].Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("type = %T", scopes[0].Metrics[0].Data)
	}
	if len(hist.DataPoints) != 1 {
		t.Fatalf("points = %d", len(hist.DataPoints))
	}
	dp := hist.DataPoints[0]
	if dp.Count != 3 {
		t.Errorf("count = %d", dp.Count)
	}
	if dp.Sum != 23.5 {
		t.Errorf("sum = %v", dp.Sum)
	}
	if len(dp.Bounds) != 3 || dp.Bounds[0] != 1 || dp.Bounds[1] != 5 || dp.Bounds[2] != 10 {
		t.Errorf("bounds = %v", dp.Bounds)
	}
	if len(dp.BucketCounts) != 4 {
		t.Errorf("bucket counts = %v", dp.BucketCounts)
	}
	if dp.BucketCounts[3] != 1 {
		t.Errorf("overflow bucket = %v", dp.BucketCounts)
	}
}

type errGatherer struct{}

func (errGatherer) Gather() ([]*dto.MetricFamily, error) {
	return nil, errors.New("boom")
}

func TestPrometheusBridge_GatherError(t *testing.T) {
	br := &prometheusBridge{gatherer: errGatherer{}}
	if _, err := br.Produce(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestPrometheusBridge_NilFamilySkipped(t *testing.T) {
	now := time.Now()
	if _, ok := convertFamily(nil, now, now); ok {
		t.Error("expected nil to be skipped")
	}
	if _, ok := convertFamily(&dto.MetricFamily{}, now, now); ok {
		t.Error("expected nameless family to be skipped")
	}
}

func TestAttrsFromLabels_Empty(t *testing.T) {
	set := attrsFromLabels(nil)
	if set.Len() != 0 {
		t.Errorf("expected empty, got %d", set.Len())
	}
}

func TestPrometheusBridge_UntypedFamilySkipped(t *testing.T) {
	name := "u"
	help := ""
	tp := dto.MetricType_SUMMARY
	fam := &dto.MetricFamily{Name: &name, Help: &help, Type: &tp}
	now := time.Now()
	if _, ok := convertFamily(fam, now, now); ok {
		t.Error("expected summary to be skipped")
	}
}
