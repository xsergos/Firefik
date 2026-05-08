//go:build linux

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestParseCounter(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"0", 0},
		{"123", 123},
		{"  42 ", 42},
		{"1K", 1000},
		{"2M", 2_000_000},
		{"3G", 3_000_000_000},
		{"abc", 0},
		{"", 0},
	}
	for _, c := range cases {
		got := parseCounter(c.in)
		if got != c.want {
			t.Errorf("parseCounter(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIPTablesCollector_Describe(t *testing.T) {
	c := &IPTablesCollector{
		packetsDesc: prometheus.NewDesc("firefik_test_packets", "test", []string{"chain", "target"}, nil),
		bytesDesc:   prometheus.NewDesc("firefik_test_bytes", "test", []string{"chain", "target"}, nil),
	}
	ch := make(chan *prometheus.Desc, 4)
	c.Describe(ch)
	close(ch)
	count := 0
	for range ch {
		count++
	}
	if count != 2 {
		t.Fatalf("expected 2 descs, got %d", count)
	}
}

func TestNFTablesCollector_Describe(t *testing.T) {
	c := &NFTablesCollector{
		packetsDesc: prometheus.NewDesc("firefik_test_nft_packets", "test", []string{"chain", "target"}, nil),
		bytesDesc:   prometheus.NewDesc("firefik_test_nft_bytes", "test", []string{"chain", "target"}, nil),
	}
	ch := make(chan *prometheus.Desc, 4)
	c.Describe(ch)
	close(ch)
	count := 0
	for range ch {
		count++
	}
	if count != 2 {
		t.Fatalf("expected 2 descs, got %d", count)
	}
}

func TestNewIPTablesCollector_RegistersOrSkips(t *testing.T) {
	prev := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	defer func() { prometheus.DefaultRegisterer = prev }()

	c, err := NewIPTablesCollector("FIREFIK")
	if err != nil {
		t.Skipf("iptables not available in test env: %v", err)
	}
	if c == nil {
		t.Fatal("nil collector with nil error")
	}
}

func TestNewNFTablesCollector_RegistersOrSkips(t *testing.T) {
	prev := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	defer func() { prometheus.DefaultRegisterer = prev }()

	c, err := NewNFTablesCollector("FIREFIK")
	if err != nil {
		t.Skipf("nftables not available in test env: %v", err)
	}
	if c == nil {
		t.Fatal("nil collector with nil error")
	}
}

func TestIPTablesCollector_Collect_HandlesErrors(t *testing.T) {
	prev := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	defer func() { prometheus.DefaultRegisterer = prev }()

	c, err := NewIPTablesCollector("FIREFIK")
	if err != nil {
		t.Skipf("iptables not available: %v", err)
	}
	ch := make(chan prometheus.Metric, 32)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	for range ch {
	}
}

func TestNFTablesCollector_Collect_HandlesErrors(t *testing.T) {
	prev := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	defer func() { prometheus.DefaultRegisterer = prev }()

	c, err := NewNFTablesCollector("FIREFIK")
	if err != nil {
		t.Skipf("nftables not available: %v", err)
	}
	ch := make(chan prometheus.Metric, 32)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	for range ch {
	}
}
