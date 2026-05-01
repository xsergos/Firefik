package controlplane

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"time"
)

type CertExpiryWatcher struct {
	CertPath string
	AgentID  string
	Interval time.Duration
	Logger   *slog.Logger
}

func (w *CertExpiryWatcher) Run(ctx context.Context) {
	if w.CertPath == "" {
		return
	}
	interval := w.Interval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	logger := w.Logger
	if logger == nil {
		logger = slog.Default()
	}
	w.observe(logger)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.observe(logger)
		}
	}
}

func (w *CertExpiryWatcher) observe(logger *slog.Logger) {
	cert, err := loadAgentCert(w.CertPath)
	if err != nil {
		logger.Warn("cert expiry watch: load failed", "path", w.CertPath, "error", err)
		return
	}
	spiffeID := firstURISAN(cert)
	days := time.Until(cert.NotAfter).Hours() / 24
	SetAgentCertExpiry(w.AgentID, spiffeID, days)
}

func loadAgentCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func firstURISAN(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, u := range cert.URIs {
		if u != nil {
			return u.String()
		}
	}
	return ""
}
