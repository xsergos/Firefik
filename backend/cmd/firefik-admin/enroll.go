package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"firefik/internal/controlplane"
)

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	endpoint := fs.String("control-plane", "", "https://host:port of firefik-server (required)")
	agentID := fs.String("agent-id", "", "agent identifier (defaults to hostname)")
	token := fs.String("token", "", "bootstrap bearer token (overrides $FIREFIK_CONTROL_PLANE_TOKEN)")
	ttl := fs.Duration("ttl", 720*time.Hour, "requested certificate TTL")
	outDir := fs.String("out", "/var/lib/firefik/control-plane", "output directory")
	renew := fs.Bool("renew", false, "only enroll if the existing cert expires within --renew-window")
	renewWindow := fs.Duration("renew-window", 72*time.Hour, "renew if cert expires within this window")
	trustDomain := fs.String("trust-domain", "", "expected SPIFFE trust domain for validation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *endpoint == "" {
		return fmt.Errorf("--control-plane required")
	}
	id := *agentID
	if id == "" {
		h, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("hostname: %w", err)
		}
		id = h
	}
	bearer := *token
	if bearer == "" {
		bearer = os.Getenv("FIREFIK_CONTROL_PLANE_TOKEN")
	}

	certPath := filepath.Join(*outDir, "client.crt")
	keyPath := filepath.Join(*outDir, "client.key")
	bundlePath := filepath.Join(*outDir, "ca-bundle.pem")

	if *renew {
		if existing, err := loadCertExpiry(certPath); err == nil {
			remaining := time.Until(existing)
			if remaining > *renewWindow {
				fmt.Printf("cert %s valid for %s; --renew window is %s. nothing to do.\n",
					certPath, remaining.Truncate(time.Second), *renewWindow)
				return nil
			}
			fmt.Printf("cert %s expires in %s — renewing.\n", certPath, remaining.Truncate(time.Second))
		}
	}

	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", *outDir, err)
	}

	client := controlplane.NewEnrollClient(*endpoint, bearer)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := client.Enroll(ctx, controlplane.EnrollRequest{
		AgentID:     id,
		TTLSeconds:  int(ttl.Seconds()),
		TrustDomain: *trustDomain,
	})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if err := os.WriteFile(certPath, []byte(resp.CertPEM), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, []byte(resp.KeyPEM), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(bundlePath, []byte(resp.BundlePEM), 0o644); err != nil {
		return err
	}
	fmt.Printf("agent-id: %s\nspiffe:   %s\nserial:   %s\nexpires:  %s\ncert:     %s\nkey:      %s\nbundle:   %s\n",
		id, resp.SPIFFEURI, resp.Serial,
		time.Unix(resp.NotAfterUnix, 0).UTC().Format(time.RFC3339),
		certPath, keyPath, bundlePath,
	)
	return nil
}

func loadCertExpiry(path string) (time.Time, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}
