package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleMetrics = `# HELP firefik_engine_reconcile_total
# TYPE firefik_engine_reconcile_total counter
firefik_engine_reconcile_total 42
firefik_engine_apply_errors_total{phase="backend"} 3
firefik_engine_apply_errors_total{phase="labels"} 1
firefik_engine_apply_errors_total{phase="kernel_emit"} 7
firefik_packets_total{action="accept",container="abc123"} 100
firefik_packets_total{action="drop",container="abc123"} 5
firefik_packets_total{action="accept",container="def456"} 200
firefik_engine_reconcile_duration_seconds_bucket{le="0.005"} 1
firefik_engine_reconcile_duration_seconds_bucket{le="0.01"} 2
firefik_engine_reconcile_duration_seconds_count 3
firefik_engine_reconcile_duration_seconds_sum 0.025
`

func TestAnalyseMetrics_Counts(t *testing.T) {
	r, err := analyseMetrics(strings.NewReader(sampleMetrics), 100)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if r.Total < 3 {
		t.Fatalf("expected ≥ 3 metrics, got %d", r.Total)
	}
	if r.Exceeded != 0 {
		t.Fatalf("expected 0 exceeded with high threshold, got %d", r.Exceeded)
	}
	want := map[string]int{
		"firefik_engine_reconcile_total":            1,
		"firefik_engine_apply_errors":               3,
		"firefik_packets":                           3,
		"firefik_engine_reconcile_duration_seconds": 4,
	}
	for _, m := range r.Metrics {
		if exp, ok := want[m.Name]; ok && m.Cardinality != exp {
			t.Errorf("metric %s cardinality = %d, want %d", m.Name, m.Cardinality, exp)
		}
	}
}

func TestAnalyseMetrics_ThresholdExceeds(t *testing.T) {
	var b bytes.Buffer
	for i := 0; i < 10; i++ {
		b.WriteString("test_metric_total{id=\"")
		b.WriteString(string(rune('a' + i)))
		b.WriteString("\"} 1\n")
	}
	r, err := analyseMetrics(&b, 5)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if r.Exceeded != 1 {
		t.Fatalf("expected 1 exceeded, got %d", r.Exceeded)
	}
	if !r.Metrics[0].Exceeds {
		t.Fatalf("expected first metric to exceed")
	}
}

func TestParseMetricLine(t *testing.T) {
	cases := []struct {
		in     string
		name   string
		labels string
	}{
		{`metric_total 1`, "metric_total", ""},
		{`metric_total{a="b"} 1`, "metric_total", `a="b"`},
		{`metric_total{a="b",c="d"} 1`, "metric_total", `a="b",c="d"`},
		{`metric_with_brace_in_value{a="x{y}"} 1`, "metric_with_brace_in_value", `a="x{y}"`},
	}
	for _, c := range cases {
		gotN, gotL := parseMetricLine(c.in)
		if gotN != c.name || gotL != c.labels {
			t.Errorf("parseMetricLine(%q) = %q,%q; want %q,%q", c.in, gotN, gotL, c.name, c.labels)
		}
	}
}

func TestBaseName(t *testing.T) {
	cases := map[string]string{
		"foo_total":  "foo",
		"foo_bucket": "foo",
		"foo_count":  "foo",
		"foo_sum":    "foo",
		"foo":        "foo",
	}
	for in, want := range cases {
		if got := baseName(in); got != want {
			t.Errorf("baseName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLabelKeyList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{`a="b"`, []string{"a"}},
		{`a="b",c="d"`, []string{"a", "c"}},
		{`a="b,c",d="e"`, []string{"a", "d"}},
	}
	for _, c := range cases {
		got := labelKeyList(c.in)
		if len(got) != len(c.want) {
			t.Errorf("labelKeyList(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("labelKeyList(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestOpenMetricsSource_File(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "metrics.txt")
	if err := os.WriteFile(tmp, []byte(sampleMetrics), 0o600); err != nil {
		t.Fatal(err)
	}
	r, c, err := openMetricsSource(tmp, "", false, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if c == nil {
		t.Fatal("expected closer for file source")
	}
	defer c.Close()
	buf := make([]byte, 32)
	if _, err := r.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
}

func TestOpenMetricsSource_HTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "no auth", 401)
			return
		}
		w.Write([]byte(sampleMetrics))
	}))
	defer srv.Close()

	r, c, err := openMetricsSource(srv.URL, "secret", false, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer c.Close()
	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(body) == 0 {
		t.Fatalf("body empty")
	}
}

func TestOpenMetricsSource_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	if _, _, err := openMetricsSource(srv.URL, "", false, 0); err == nil {
		t.Fatal("expected error on 503")
	}
}

func TestOpenMetricsSourceBadFile(t *testing.T) {
	if _, _, err := openMetricsSource("/no/such/file", "", false, 0); err == nil {
		t.Errorf("expected error")
	}
}

func TestOpenMetricsSourceBadURL(t *testing.T) {
	if _, _, err := openMetricsSource("http://", "", false, 0); err == nil {
		t.Errorf("expected error")
	}
}

func TestCmdMetricsAuditFromFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "metrics.txt")
	if err := os.WriteFile(tmp, []byte(sampleMetrics), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = captureStdout(t, func() {
		_ = cmdMetricsAudit([]string{"--source", tmp, "--threshold", "1000"})
	})
}

func TestCmdMetricsAuditFromFileJSON(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "metrics.txt")
	if err := os.WriteFile(tmp, []byte(sampleMetrics), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		_ = cmdMetricsAudit([]string{"--source", tmp, "--threshold", "1000", "--output", "json"})
	})
	if !strings.Contains(out, "total_metrics") {
		t.Errorf("expected JSON: %s", out)
	}
}

func TestCmdMetricsAuditFlagError(t *testing.T) {
	if err := cmdMetricsAudit([]string{"--bogus"}); err == nil {
		t.Errorf("expected flag error")
	}
}

func TestCmdMetricsAuditOpenError(t *testing.T) {
	err := cmdMetricsAudit([]string{"--source", "/no/such/file"})
	if err == nil {
		t.Errorf("expected open error")
	}
}

func TestPrintMetricsAudit(t *testing.T) {
	report := &metricsAuditReport{
		Threshold: 100,
		Total:     2,
		Exceeded:  1,
		Metrics: []metricCardinality{
			{Name: "high", Cardinality: 200, LabelKeys: []string{"a", "b"}, Exceeds: true},
			{Name: "low", Cardinality: 5, LabelKeys: nil, Exceeds: false},
		},
	}
	var w bytes.Buffer
	printMetricsAudit(&w, report)
	out := w.String()
	if !strings.Contains(out, "Metrics analysed: 2") {
		t.Errorf("missing total: %s", out)
	}
	if !strings.Contains(out, "Exceeding threshold: 1") {
		t.Errorf("missing exceeded: %s", out)
	}
	if !strings.Contains(out, "high") || !strings.Contains(out, "low") {
		t.Errorf("missing rows: %s", out)
	}
}
