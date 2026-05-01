package controlplane

import "testing"

func TestIncCACertsIssued(t *testing.T) {
	IncCACertsIssued()
	IncCACertsIssued()
}

func TestIncMTLSRejected(t *testing.T) {
	IncMTLSRejected("test")
	IncMTLSRejected("other")
}

func TestSetAgentCertExpiry(t *testing.T) {
	SetAgentCertExpiry("agent1", "spiffe://x", 30)
	SetAgentCertExpiry("agent1", "spiffe://x", -1)
}
