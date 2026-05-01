package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNewRegistry(t *testing.T) {
	prev := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
	defer func() { prometheus.DefaultRegisterer = prev }()

	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if r.RulesActive == nil || r.PacketsTotal == nil || r.ReconcileDuration == nil || r.DockerEventsTotal == nil {
		t.Errorf("registry has nil fields: %+v", r)
	}

	r.RulesActive.WithLabelValues("c1").Set(3)
	r.PacketsTotal.WithLabelValues("c1", "ACCEPT").Inc()
	r.ReconcileDuration.Observe(0.5)
	r.DockerEventsTotal.WithLabelValues("start").Inc()
}
