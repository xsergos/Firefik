package controlplane

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	grpcConnectedAgents = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "firefik_controlplane_grpc_agents_connected",
		Help: "Currently connected agents on the gRPC Stream RPC.",
	})

	ConnectionState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "firefik_controlplane_connection_state",
		Help: "Agent-side control-plane connection state (1=connected, 0.5=reconnecting, 0=backoff, -1=disabled).",
	}, []string{"peer", "transport"})

	TransportMix = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "firefik_controlplane_transport_requests_total",
		Help: "Control-plane requests accepted by the server, keyed by transport.",
	}, []string{"transport"})

	cpMTLSRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "firefik_controlplane_mtls_rejected_total",
		Help: "Peer certificates rejected by SPIFFE trust-domain enforcement.",
	}, []string{"reason"})

	cpCACertsIssuedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "firefik_controlplane_ca_certs_issued_total",
		Help: "Agent certificates issued through the /v1/enroll bootstrap endpoint.",
	})

	cpAuditEventsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "firefik_controlplane_audit_events_total",
		Help: "Audit events persisted by the control-plane store.",
	})

	cpDBBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "firefik_controlplane_db_bytes",
		Help: "Control-plane sqlite database size on disk (bytes).",
	})

	cpAgentCommandsEnqueued = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "firefik_controlplane_commands_enqueued_total",
		Help: "Commands enqueued to per-agent queues, by kind.",
	}, []string{"kind"})

	AgentCertDaysUntilExpiry = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "firefik_controlplane_agent_cert_days_until_expiry",
		Help: "Days until the agent's mTLS client certificate expires. Negative means expired.",
	}, []string{"agent_id", "spiffe_id"})
)

func IncCACertsIssued() { cpCACertsIssuedTotal.Inc() }

func IncMTLSRejected(reason string) { cpMTLSRejectedTotal.WithLabelValues(reason).Inc() }

func SetAgentCertExpiry(agentID, spiffeID string, daysUntil float64) {
	AgentCertDaysUntilExpiry.WithLabelValues(agentID, spiffeID).Set(daysUntil)
}
