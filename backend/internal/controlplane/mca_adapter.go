package controlplane

import (
	"time"

	"firefik/internal/controlplane/mca"
)

type MCAAdapter struct{ CA *mca.CA }

func (a MCAAdapter) Issue(req CAIssueRequest) (*CAIssueResult, error) {
	r, err := a.CA.Issue(mca.IssueRequest{AgentID: req.AgentID, TTL: req.TTL, PublicKey: req.PublicKey})
	if err != nil {
		return nil, err
	}
	return &CAIssueResult{
		CertPEM:   r.CertPEM,
		KeyPEM:    r.KeyPEM,
		BundlePEM: r.BundlePEM,
		SerialHex: r.SerialHex,
		NotAfter:  r.NotAfter,
		SPIFFEURI: r.SPIFFEURI,
	}, nil
}

func (a MCAAdapter) IssueFromCSR(csrPEM []byte, agentID string, ttl time.Duration) (*CAIssueResult, error) {
	r, err := a.CA.IssueFromCSR(csrPEM, agentID, ttl)
	if err != nil {
		return nil, err
	}
	return &CAIssueResult{
		CertPEM:   r.CertPEM,
		KeyPEM:    r.KeyPEM,
		BundlePEM: r.BundlePEM,
		SerialHex: r.SerialHex,
		NotAfter:  r.NotAfter,
		SPIFFEURI: r.SPIFFEURI,
	}, nil
}

func (a MCAAdapter) IsRevoked(serial string) bool {
	return a.CA.IsRevoked(serial)
}

func (a MCAAdapter) TrustBundlePEM() []byte {
	return a.CA.TrustBundlePEM()
}
