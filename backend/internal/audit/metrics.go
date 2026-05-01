package audit

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var webhookSentTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "firefik_webhook_sent_total",
	Help: "Total webhook delivery attempts, grouped by HTTP status class.",
}, []string{"status"})
