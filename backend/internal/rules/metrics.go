package rules

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	reconcileTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "firefik_engine_reconcile_total",
		Help: "Total number of engine reconcile cycles attempted.",
	})
	reconcileErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "firefik_engine_reconcile_errors_total",
		Help: "Total number of engine reconcile cycles that returned an error.",
	})
	reconcileDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "firefik_engine_reconcile_duration_seconds",
		Help:    "Wall-clock duration of a full engine reconcile cycle.",
		Buckets: prometheus.DefBuckets,
	})

	applyDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "firefik_engine_apply_duration_seconds",
		Help:    "Wall-clock duration of a single container rule-apply operation.",
		Buckets: prometheus.DefBuckets,
	}, []string{"result"})
	applyErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "firefik_engine_apply_errors_total",
		Help: "Total rule-apply errors, grouped by failure phase.",
	}, []string{"phase"})

	orphansCleanedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "firefik_engine_orphans_cleaned_total",
		Help: "Total orphan container chains removed by reconcile (dead containers with residual kernel rules).",
	})

	rehydratedChains = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "firefik_engine_rehydrated_chains",
		Help: "Number of container chains found in the kernel at startup (pre-Reconcile).",
	})

	LegacyCleanupErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "firefik_engine_legacy_cleanup_errors_total",
		Help: "Blue/green legacy-chain cleanup failures, labelled by suffix.",
	}, []string{"suffix"})

	driftTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "firefik_engine_drift_total",
		Help: "Drift between in-memory applied state and kernel state, by type.",
	}, []string{"type"})

	driftChecksTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "firefik_engine_drift_checks_total",
		Help: "Total drift-detection cycles attempted.",
	})

	driftCheckErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "firefik_engine_drift_check_errors_total",
		Help: "Drift-detection cycles that failed to enumerate kernel state.",
	})

	scheduledReconcileTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "firefik_engine_scheduled_reconcile_total",
		Help: "Reconciles triggered by the time-window scheduler when any container has a scheduled rule-set.",
	})
	scheduledToggleTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "firefik_engine_scheduled_toggle_total",
		Help: "Rule-set activity transitions observed by the scheduler, by direction.",
	}, []string{"direction"})

	AutogenRecordedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "firefik_autogen_flows_recorded_total",
		Help: "NFLOG flows that the autogen observer recorded (observe-mode only).",
	})
	AutogenResolveMissTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "firefik_autogen_resolve_miss_total",
		Help: "NFLOG flows discarded by autogen because neither endpoint IP mapped to a known container.",
	})
)
