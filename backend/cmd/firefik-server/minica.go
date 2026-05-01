package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"firefik/internal/controlplane/mca"
)

func runMiniCA(args []string) error {
	if len(args) == 0 {
		miniCAUsage()
		return fmt.Errorf("mini-ca: subcommand required")
	}
	switch args[0] {
	case "init":
		return miniCAInit(args[1:])
	case "issue":
		return miniCAIssue(args[1:])
	case "-h", "--help", "help":
		miniCAUsage()
		return nil
	default:
		miniCAUsage()
		return fmt.Errorf("mini-ca: unknown subcommand %q", args[0])
	}
}

func miniCAUsage() {
	fmt.Fprintln(os.Stderr, "usage: firefik-server mini-ca <init|issue> [flags]")
	fmt.Fprintln(os.Stderr, "  init   --state-dir <path> [--trust-domain spiffe://...]")
	fmt.Fprintln(os.Stderr, "  issue  --state-dir <path> --agent-id <id> [--ttl 720h] [--out <dir>]")
}

func miniCAInit(args []string) error {
	fs := flag.NewFlagSet("mini-ca init", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultCAStateDir(), "CA state directory")
	trustDomain := fs.String("trust-domain", "firefik.local", "SPIFFE trust domain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ca, err := mca.Init(*stateDir, *trustDomain)
	if err != nil {
		return fmt.Errorf("init CA: %w", err)
	}
	fmt.Printf("CA ready at %s\n", *stateDir)
	fmt.Printf("trust-domain: %s\n", *trustDomain)
	fmt.Printf("root not-after: %s\n", ca.RootCert().NotAfter.Format(time.RFC3339))
	return nil
}

func miniCAIssue(args []string) error {
	fs := flag.NewFlagSet("mini-ca issue", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultCAStateDir(), "CA state directory")
	agentID := fs.String("agent-id", "", "agent identifier (required)")
	ttl := fs.Duration("ttl", 720*time.Hour, "certificate TTL")
	trustDomain := fs.String("trust-domain", "firefik.local", "SPIFFE trust domain")
	outDir := fs.String("out", ".", "output directory for cert / key / bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agentID == "" {
		return fmt.Errorf("--agent-id required")
	}
	ca, err := mca.Open(*stateDir, *trustDomain)
	if err != nil {
		return fmt.Errorf("open CA: %w", err)
	}
	res, err := ca.Issue(mca.IssueRequest{AgentID: *agentID, TTL: *ttl})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	certPath := filepath.Join(*outDir, *agentID+".crt")
	keyPath := filepath.Join(*outDir, *agentID+".key")
	bundlePath := filepath.Join(*outDir, "ca-bundle.pem")
	if err := os.WriteFile(certPath, res.CertPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, res.KeyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(bundlePath, res.BundlePEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("cert:   %s\nkey:    %s\nbundle: %s\nserial: %s\nspiffe: %s\nexpires: %s\n",
		certPath, keyPath, bundlePath, res.SerialHex, res.SPIFFEURI, res.NotAfter.Format(time.RFC3339))
	return nil
}

func defaultCAStateDir() string {
	if v := os.Getenv("FIREFIK_CP_CA_DIR"); v != "" {
		return v
	}
	return "/var/lib/firefik-server/ca"
}
