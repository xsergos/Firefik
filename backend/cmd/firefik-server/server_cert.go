package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"firefik/internal/controlplane"
	"firefik/internal/controlplane/mca"
)

type serverCertManager struct {
	CA          *mca.CA
	CertPath    string
	KeyPath     string
	DNSNames    []string
	IPAddresses []string
	TTL         time.Duration
	RenewBefore time.Duration
	Logger      *slog.Logger
	Audit       controlplane.AuditEmitter

	loader *controlplane.KeypairLoader
}

func (m *serverCertManager) ensureAtStartup() error {
	if m.CertPath == "" || m.KeyPath == "" {
		return errors.New("cert/key paths required")
	}
	reason := m.shouldReissue()
	if reason == "" {
		if m.Logger != nil {
			m.Logger.Info("server cert OK", "path", m.CertPath)
		}
		return nil
	}
	return m.issue(reason)
}

func (m *serverCertManager) shouldReissue() string {
	cert, err := loadCertFile(m.CertPath)
	if err != nil {
		return "missing"
	}
	if !certHasAllSANs(cert, m.DNSNames, m.IPAddresses) {
		return "san_mismatch"
	}
	if m.CA != nil {
		if err := verifyAgainstIssuer(cert, m.CA); err != nil {
			return "issuer_rotated"
		}
	}
	if m.RenewBefore > 0 && time.Until(cert.NotAfter) < m.RenewBefore {
		return "near_expiry"
	}
	return ""
}

func (m *serverCertManager) issue(reason string) error {
	if m.CA == nil {
		return errors.New("mini-CA not available")
	}
	res, err := m.CA.IssueServerCert(mca.ServerCertRequest{
		DNSNames:    m.DNSNames,
		IPAddresses: m.IPAddresses,
		TTL:         m.TTL,
	})
	if err != nil {
		controlplane.IncServerCertRenewFailed(reason)
		return fmt.Errorf("issue server cert: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(m.CertPath), 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(m.CertPath, res.CertPEM, 0o644); err != nil {
		controlplane.IncServerCertRenewFailed("write_cert")
		return err
	}
	if err := writeFileAtomic(m.KeyPath, res.KeyPEM, 0o600); err != nil {
		controlplane.IncServerCertRenewFailed("write_key")
		return err
	}
	controlplane.IncServerCertRenewed(reason)
	if m.Audit != nil {
		m.Audit.Emit("server_cert_rotated", map[string]string{
			"reason":     reason,
			"serial":     res.SerialHex,
			"expires_at": res.NotAfter.Format(time.RFC3339),
		})
	}
	if m.Logger != nil {
		m.Logger.Info("server cert rotated",
			"reason", reason,
			"serial", res.SerialHex,
			"expires_at", res.NotAfter.Format(time.RFC3339),
		)
	}
	return nil
}

func (m *serverCertManager) runDaily(ctx context.Context) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if reason := m.shouldReissue(); reason != "" {
				if err := m.issue(reason); err != nil && m.Logger != nil {
					m.Logger.Warn("daily server-cert rotation failed", "reason", reason, "error", err)
				}
			}
		}
	}
}

func loadCertFile(path string) (*x509.Certificate, error) {
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

func certHasAllSANs(cert *x509.Certificate, dns, ips []string) bool {
	for _, n := range dns {
		if !contains(cert.DNSNames, n) {
			return false
		}
	}
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		found := false
		for _, c := range cert.IPAddresses {
			if c.Equal(parsed) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func verifyAgainstIssuer(cert *x509.Certificate, ca *mca.CA) error {
	pool := ca.ClientCAPool()
	_, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func defaultServerNames() []string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return []string{"controlplane"}
	}
	return []string{strings.ToLower(h), "controlplane"}
}

func resolveServerCertPaths(certFlag, keyFlag, caStateDir, prefixOverride string, haveCA bool) (cert, key string, auto bool) {
	if certFlag != "" || keyFlag != "" {
		return certFlag, keyFlag, false
	}
	if !haveCA {
		return "", "", false
	}
	prefix := prefixOverride
	if prefix == "" {
		prefix = filepath.Join(caStateDir, "cp-server")
	}
	return prefix + ".crt", prefix + ".key", true
}
