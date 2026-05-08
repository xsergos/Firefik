package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"firefik/internal/controlplane"
	"firefik/internal/controlplane/mca"
)

const minRenewWindow = 24 * time.Hour

func makeRenewHandler(ca *mca.CA, trustDomain string, audit controlplane.AuditEmitter, logger *slog.Logger) controlplane.EnrollHandler {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			controlplane.IncRenewRejected("no_peer_cert")
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		peer := r.TLS.PeerCertificates[0]

		if trustDomain != "" {
			verify := mca.VerifySPIFFEPeer(trustDomain)
			if err := verify([][]byte{peer.Raw}, nil); err != nil {
				controlplane.IncRenewRejected("trust_domain")
				controlplane.IncMTLSRejected("trust_domain")
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
		}

		certAgentID := agentIDFromSPIFFE(peer)
		if certAgentID == "" {
			controlplane.IncRenewRejected("no_spiffe_san")
			http.Error(w, "peer cert lacks SPIFFE agent SAN", http.StatusForbidden)
			return
		}

		peerSerial := strings.ToLower(peer.SerialNumber.Text(16))
		if ca.IsRevoked(peerSerial) {
			controlplane.IncRenewRejected("revoked")
			if audit != nil {
				audit.Emit("cert_renew_rejected", map[string]string{
					"agent_id": certAgentID,
					"serial":   peerSerial,
					"reason":   "revoked",
				})
			}
			http.Error(w, "client certificate is revoked", http.StatusForbidden)
			return
		}

		var req controlplane.RenewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("decode: %v", err), http.StatusBadRequest)
			return
		}
		if req.AgentID == "" {
			req.AgentID = certAgentID
		}
		if req.AgentID != certAgentID {
			controlplane.IncRenewRejected("id_mismatch")
			http.Error(w, "agent_id does not match peer certificate", http.StatusForbidden)
			return
		}

		remaining := time.Until(peer.NotAfter)
		if remaining > minRenewWindow {
			controlplane.IncRenewRejected("not_in_window")
			http.Error(w, fmt.Sprintf("certificate valid for %s; renew window is %s", remaining.Truncate(time.Second), minRenewWindow), http.StatusTooEarly)
			return
		}

		ttl := time.Duration(req.TTLSeconds) * time.Second
		var (
			result *mca.IssueResult
			issErr error
		)
		if req.CSRPEM != "" {
			if !csrPubKeyMatchesPeer([]byte(req.CSRPEM), peer) {
				controlplane.IncRenewRejected("csr_pubkey_mismatch")
				http.Error(w, "CSR public key must match the peer cert public key", http.StatusBadRequest)
				return
			}
			result, issErr = ca.IssueFromCSR([]byte(req.CSRPEM), req.AgentID, ttl)
		} else {
			result, issErr = ca.Issue(mca.IssueRequest{AgentID: req.AgentID, TTL: ttl})
		}
		if issErr != nil {
			logger.Warn("renew issue failed", "agent_id", req.AgentID, "error", issErr)
			controlplane.IncRenewRejected("issue_failed")
			http.Error(w, "issue failed", http.StatusInternalServerError)
			return
		}

		oldSerial := peer.SerialNumber.Text(16)
		controlplane.IncCertRenewed()
		if audit != nil {
			audit.Emit("cert_renewed", map[string]string{
				"agent_id":   req.AgentID,
				"serial_old": oldSerial,
				"serial_new": result.SerialHex,
				"expires_at": result.NotAfter.Format(time.RFC3339),
			})
		}
		logger.Info("agent certificate renewed", "agent_id", req.AgentID, "serial_old", oldSerial, "serial_new", result.SerialHex)

		resp := controlplane.RenewResponse{
			CertPEM:      string(result.CertPEM),
			KeyPEM:       string(result.KeyPEM),
			BundlePEM:    string(result.BundlePEM),
			Serial:       result.SerialHex,
			SPIFFEURI:    result.SPIFFEURI,
			NotAfterUnix: result.NotAfter.Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func csrPubKeyMatchesPeer(csrPEM []byte, peer *x509.Certificate) bool {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return false
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return false
	}
	csrPub, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return false
	}
	peerPub, err := x509.MarshalPKIXPublicKey(peer.PublicKey)
	if err != nil {
		return false
	}
	return bytes.Equal(csrPub, peerPub)
}

func agentIDFromSPIFFE(cert *x509.Certificate) string {
	for _, u := range cert.URIs {
		if u == nil {
			continue
		}
		s := u.String()
		const marker = "/agent/"
		if i := strings.Index(s, marker); i >= 0 {
			return s[i+len(marker):]
		}
	}
	return ""
}
