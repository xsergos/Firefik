package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Registry struct {
	RulesActive       *prometheus.GaugeVec
	PacketsTotal      *prometheus.CounterVec
	ReconcileDuration prometheus.Histogram
	DockerEventsTotal *prometheus.CounterVec
}

func NewRegistry() *Registry {
	return &Registry{
		RulesActive: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "firefik_rules_active",
			Help: "Number of active iptables rules managed by firefik, per container.",
		}, []string{"container"}),

		PacketsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "firefik_packets_total",
			Help: "Total packets processed by firefik chains, by container and action.",
		}, []string{"container", "action"}),

		ReconcileDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "firefik_reconcile_duration_seconds",
			Help:    "Duration of a full engine reconcile cycle.",
			Buckets: prometheus.DefBuckets,
		}),

		DockerEventsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "firefik_docker_events_total",
			Help: "Total Docker container events handled by firefik.",
		}, []string{"event_type"}),
	}
}
