package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"firefik/internal/controlplane"
	"firefik/internal/controlplane/mca"
)

const testTrustDomain = "spiffe://test.firefik/"

type capturingAudit struct {
	events []string
}

func (c *capturingAudit) Emit(action string, _ map[string]string) {
	c.events = append(c.events, action)
}

func newTestCA(t *testing.T) *mca.CA {
	t.Helper()
	dir := t.TempDir()
	ca, err := mca.Init(dir, testTrustDomain)
	if err != nil {
		t.Fatalf("init mini-CA: %v", err)
	}
	return ca
}

func issueAgentCert(t *testing.T, ca *mca.CA, agentID string) (cert *x509.Certificate, certPEM, keyPEM []byte) {
	t.Helper()
	res, err := ca.Issue(mca.IssueRequest{AgentID: agentID})
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	block, _ := pem.Decode(res.CertPEM)
	if block == nil {
		t.Fatal("no cert PEM block")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return parsed, res.CertPEM, res.KeyPEM
}

func reqWithPeer(method, path, body string, peer *x509.Certificate) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if peer != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	}
	return r
}

func TestRenewHandler_MethodNotAllowed(t *testing.T) {
	h := makeRenewHandler(newTestCA(t), testTrustDomain, nil, slog.Default())
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/renew", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestRenewHandler_NoPeerCert(t *testing.T) {
	h := makeRenewHandler(newTestCA(t), testTrustDomain, nil, slog.Default())
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/v1/renew", strings.NewReader(`{"agent_id":"a"}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestRenewHandler_WrongTrustDomain(t *testing.T) {
	ca := newTestCA(t)
	peer, _, _ := issueAgentCert(t, ca, "agent-a")
	h := makeRenewHandler(ca, "spiffe://other.firefik/", nil, slog.Default())
	rec := httptest.NewRecorder()
	h(rec, reqWithPeer(http.MethodPost, "/v1/renew", `{"agent_id":"agent-a"}`, peer))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestRenewHandler_AgentIDMismatch(t *testing.T) {
	ca := newTestCA(t)
	peer, _, _ := issueAgentCert(t, ca, "agent-a")
	h := makeRenewHandler(ca, testTrustDomain, nil, slog.Default())
	rec := httptest.NewRecorder()
	h(rec, reqWithPeer(http.MethodPost, "/v1/renew", `{"agent_id":"agent-b"}`, peer))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestRenewHandler_NotInWindow(t *testing.T) {
	ca := newTestCA(t)
	peer, _, _ := issueAgentCert(t, ca, "agent-a")
	h := makeRenewHandler(ca, testTrustDomain, nil, slog.Default())
	rec := httptest.NewRecorder()
	h(rec, reqWithPeer(http.MethodPost, "/v1/renew", `{"agent_id":"agent-a"}`, peer))
	if rec.Code != http.StatusTooEarly {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestRenewHandler_HappyPath(t *testing.T) {
	ca := newTestCA(t)
	peer, _, _ := issueAgentCert(t, ca, "agent-a")

	peer.NotAfter = peer.NotBefore.Add(2 * minRenewWindow / 2)

	audit := &capturingAudit{}
	h := makeRenewHandler(ca, testTrustDomain, audit, slog.Default())
	rec := httptest.NewRecorder()
	h(rec, reqWithPeer(http.MethodPost, "/v1/renew", `{"agent_id":"agent-a","ttl_seconds":3600}`, peer))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
	var resp controlplane.RenewResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Serial == "" || resp.CertPEM == "" {
		t.Fatalf("incomplete response: %+v", resp)
	}
	if resp.SPIFFEURI == "" || !strings.Contains(resp.SPIFFEURI, "/agent/agent-a") {
		t.Fatalf("bad spiffe uri: %q", resp.SPIFFEURI)
	}
	if len(audit.events) != 1 || audit.events[0] != "cert_renewed" {
		t.Fatalf("audit events=%v", audit.events)
	}
}

func TestRenewHandler_AgentIDInferredFromCert(t *testing.T) {
	ca := newTestCA(t)
	peer, _, _ := issueAgentCert(t, ca, "agent-a")
	peer.NotAfter = peer.NotBefore.Add(minRenewWindow / 2)

	h := makeRenewHandler(ca, testTrustDomain, nil, slog.Default())
	rec := httptest.NewRecorder()
	h(rec, reqWithPeer(http.MethodPost, "/v1/renew", `{}`, peer))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func makeCSR(t *testing.T, agentID string) (csrPEM []byte, priv *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: agentID}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

func TestRenewHandler_CSR_PubKeyMismatch(t *testing.T) {
	ca := newTestCA(t)
	peer, _, _ := issueAgentCert(t, ca, "agent-a")
	peer.NotAfter = peer.NotBefore.Add(minRenewWindow / 2)

	csrPEM, _ := makeCSR(t, "agent-a")

	h := makeRenewHandler(ca, testTrustDomain, nil, slog.Default())
	rec := httptest.NewRecorder()
	body := struct {
		AgentID string `json:"agent_id"`
		CSRPEM  string `json:"csr_pem"`
	}{AgentID: "agent-a", CSRPEM: string(csrPEM)}
	raw, _ := json.Marshal(body)
	h(rec, reqWithPeer(http.MethodPost, "/v1/renew", string(raw), peer))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestRenewHandler_CSR_HappyPath(t *testing.T) {
	ca := newTestCA(t)
	peer, _, _ := issueAgentCert(t, ca, "agent-a")
	peer.NotAfter = peer.NotBefore.Add(minRenewWindow / 2)

	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent-a"}}
	signer, ok := peer.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Skip("peer cert pubkey type not ecdsa")
	}
	_ = signer
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	peer.PublicKey = &priv.PublicKey

	h := makeRenewHandler(ca, testTrustDomain, nil, slog.Default())
	rec := httptest.NewRecorder()
	body := struct {
		AgentID string `json:"agent_id"`
		CSRPEM  string `json:"csr_pem"`
	}{AgentID: "agent-a", CSRPEM: string(csrPEM)}
	raw, _ := json.Marshal(body)
	h(rec, reqWithPeer(http.MethodPost, "/v1/renew", string(raw), peer))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
	var resp controlplane.RenewResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.KeyPEM != "" {
		t.Fatal("CSR-mode response must not contain a private key")
	}
	if resp.CertPEM == "" {
		t.Fatal("missing cert in CSR-mode response")
	}
}

func TestRenewHandler_Revoked(t *testing.T) {
	ca := newTestCA(t)
	peer, _, _ := issueAgentCert(t, ca, "agent-a")
	peer.NotAfter = peer.NotBefore.Add(minRenewWindow / 2)

	if err := ca.Revoke(peer.SerialNumber.Text(16), "test"); err != nil {
		t.Fatal(err)
	}

	audit := &capturingAudit{}
	h := makeRenewHandler(ca, testTrustDomain, audit, slog.Default())
	rec := httptest.NewRecorder()
	h(rec, reqWithPeer(http.MethodPost, "/v1/renew", `{"agent_id":"agent-a"}`, peer))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%q", rec.Code, rec.Body.String())
	}
	if len(audit.events) != 1 || audit.events[0] != "cert_renew_rejected" {
		t.Fatalf("audit events=%v", audit.events)
	}
}

func TestAgentIDFromSPIFFE(t *testing.T) {
	ca := newTestCA(t)
	cert, _, _ := issueAgentCert(t, ca, "agent-xyz")
	if got := agentIDFromSPIFFE(cert); got != "agent-xyz" {
		t.Fatalf("got %q", got)
	}
	if got := agentIDFromSPIFFE(&x509.Certificate{}); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}
