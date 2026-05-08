package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type EnrollRequest struct {
	AgentID         string `json:"agent_id"`
	TTLSeconds      int    `json:"ttl_seconds,omitempty"`
	TrustDomain     string `json:"trust_domain,omitempty"`
	EnrollmentToken string `json:"enrollment_token,omitempty"`
}

type EnrollResponse struct {
	CertPEM      string `json:"cert_pem"`
	KeyPEM       string `json:"key_pem"`
	BundlePEM    string `json:"bundle_pem"`
	Serial       string `json:"serial"`
	SPIFFEURI    string `json:"spiffe_uri"`
	NotAfterUnix int64  `json:"not_after_unix"`
}

type RenewRequest struct {
	AgentID    string `json:"agent_id"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	CSRPEM     string `json:"csr_pem,omitempty"`
}

type RenewResponse = EnrollResponse

type EnrollClient struct {
	Endpoint string
	Token    string
	HTTP     *http.Client
}

func NewEnrollClient(endpoint, token string) *EnrollClient {
	return &EnrollClient{
		Endpoint: endpoint,
		Token:    token,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *EnrollClient) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+"/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enroll returned %d: %s", resp.StatusCode, string(raw))
	}
	var out EnrollResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode enroll: %w", err)
	}
	return &out, nil
}

type RenewClient struct {
	Endpoint string
	HTTP     *http.Client
}

func NewRenewClient(endpoint, certPath, keyPath, caPath string) (*RenewClient, error) {
	return NewRenewClientWithOptions(endpoint, certPath, keyPath, caPath, false)
}

func NewRenewClientWithOptions(endpoint, certPath, keyPath, caPath string, insecureSkipVerify bool) (*RenewClient, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecureSkipVerify}
	if caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no certs in %s", caPath)
		}
		tlsCfg.RootCAs = pool
	}
	loader := newKeyPairLoader(certPath, keyPath)
	tlsCfg.GetClientCertificate = loader.getClientCertificate
	return &RenewClient{
		Endpoint: endpoint,
		HTTP: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

func (c *RenewClient) Renew(ctx context.Context, req RenewRequest) (*RenewResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+"/v1/renew", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("renew returned %d: %s", resp.StatusCode, string(raw))
	}
	var out RenewResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode renew: %w", err)
	}
	return &out, nil
}
