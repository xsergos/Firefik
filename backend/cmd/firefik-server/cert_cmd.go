package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"firefik/internal/controlplane/mca"
)

func runCert(args []string) error {
	if len(args) == 0 {
		certUsage()
		return fmt.Errorf("cert: subcommand required")
	}
	switch args[0] {
	case "rotate":
		return certRotate(args[1:])
	case "-h", "--help", "help":
		certUsage()
		return nil
	default:
		certUsage()
		return fmt.Errorf("cert: unknown subcommand %q", args[0])
	}
}

func certUsage() {
	fmt.Fprintln(os.Stderr, "usage: firefik-server cert <rotate> [flags]")
	fmt.Fprintln(os.Stderr, "  rotate  --ca-state-dir <path> [--server-cert-keypair <prefix>]")
	fmt.Fprintln(os.Stderr, "          [--server-name <name>] [--server-cert-ttl 8760h] [--force]")
}

func certRotate(args []string) error {
	fs := flag.NewFlagSet("cert rotate", flag.ContinueOnError)
	caStateDir := fs.String("ca-state-dir", defaultCAStateDir(), "mini-CA state directory")
	prefix := fs.String("server-cert-keypair", "", "path prefix for server cert (default <ca-state-dir>/cp-server)")
	namesCSV := fs.String("server-name", "", "comma-separated DNS SANs (default: hostname,controlplane)")
	ttl := fs.Duration("server-cert-ttl", 365*24*time.Hour, "TTL for the new server cert")
	force := fs.Bool("force", false, "rotate unconditionally instead of only when near expiry / SAN-mismatch / issuer-rotated")
	trustDomain := fs.String("trust-domain", trustDomainFromEnv(), "SPIFFE trust domain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *prefix == "" {
		*prefix = filepath.Join(*caStateDir, "cp-server")
	}
	dnsNames := splitCSV(*namesCSV)
	if len(dnsNames) == 0 {
		dnsNames = defaultServerNames()
	}

	ca, err := mca.Open(*caStateDir, *trustDomain)
	if err != nil {
		return fmt.Errorf("open mini-CA: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	mgr := &serverCertManager{
		CA:          ca,
		CertPath:    *prefix + ".crt",
		KeyPath:     *prefix + ".key",
		DNSNames:    dnsNames,
		IPAddresses: []string{"127.0.0.1", "::1"},
		TTL:         *ttl,
		RenewBefore: 30 * 24 * time.Hour,
		Logger:      logger,
	}
	reason := "manual"
	if !*force {
		if r := mgr.shouldReissue(); r == "" {
			fmt.Println("server cert OK; nothing to do (use --force to rotate anyway)")
			return nil
		} else {
			reason = r
		}
	}
	if err := mgr.issue(reason); err != nil {
		return err
	}
	fmt.Printf("server cert rotated: reason=%s\n", reason)
	return nil
}
