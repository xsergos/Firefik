package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type EnrollRequest struct {
	AgentID     string `json:"agent_id"`
	TTLSeconds  int    `json:"ttl_seconds,omitempty"`
	TrustDomain string `json:"trust_domain,omitempty"`
}

type EnrollResponse struct {
	CertPEM      string `json:"cert_pem"`
	KeyPEM       string `json:"key_pem"`
	BundlePEM    string `json:"bundle_pem"`
	Serial       string `json:"serial"`
	SPIFFEURI    string `json:"spiffe_uri"`
	NotAfterUnix int64  `json:"not_after_unix"`
}

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
