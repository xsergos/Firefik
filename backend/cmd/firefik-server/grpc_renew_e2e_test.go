package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"firefik/internal/controlplane"
	pb "firefik/internal/controlplane/gen/controlplanev1"
	"firefik/internal/controlplane/mca"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func TestE2E_GRPCRenew(t *testing.T) {
	caDir := t.TempDir()
	ca, err := mca.Init(caDir, "spiffe://test.firefik/")
	if err != nil {
		t.Fatal(err)
	}

	srvCert, err := ca.IssueServerCert(mca.ServerCertRequest{
		DNSNames:    []string{"localhost"},
		IPAddresses: []string{"127.0.0.1"},
		TTL:         time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	srvTLS, err := tls.X509KeyPair(srvCert.CertPEM, srvCert.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	agentCert, err := ca.Issue(mca.IssueRequest{AgentID: "agent-e2e", TTL: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	grpcTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvTLS},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.ClientCAPool(),
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return mca.VerifySPIFFEPeer("spiffe://test.firefik/")(rawCerts, nil)
		},
	}

	store := controlplane.NewMemoryStore()
	registry := controlplane.NewRegistryWithStore(slog.Default(), store)
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(grpcTLS)))
	t.Cleanup(func() { gs.Stop() })
	grpcSvc := &controlplane.GRPCServer{
		Registry:         registry,
		Logger:           slog.Default(),
		CA:               controlplane.MCAAdapter{CA: ca},
		TrustDomain:      "spiffe://test.firefik/",
		RenewWindow:      24 * time.Hour,
		MinRenewInterval: 100 * time.Millisecond,
	}
	pb.RegisterControlPlaneServer(gs, grpcSvc)
	go func() { _ = gs.Serve(listener) }()

	bundleDir := t.TempDir()
	certPath := filepath.Join(bundleDir, "client.crt")
	keyPath := filepath.Join(bundleDir, "client.key")
	bundlePath := filepath.Join(bundleDir, "bundle.pem")
	rootBundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvCert.CertPEM[:0]})
	_ = rootBundle
	if err := os.WriteFile(certPath, agentCert.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, agentCert.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, []byte("STALE BUNDLE"), 0o644); err != nil {
		t.Fatal(err)
	}

	clientTLS := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: "localhost",
		RootCAs: func() *x509.CertPool {
			p := x509.NewCertPool()
			p.AppendCertsFromPEM(srvCert.CertPEM)
			return p
		}(),
		Certificates: []tls.Certificate{
			func() tls.Certificate {
				p, err := tls.X509KeyPair(agentCert.CertPEM, agentCert.KeyPEM)
				if err != nil {
					t.Fatal(err)
				}
				return p
			}(),
		},
	}
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	rc := pb.NewControlPlaneClient(conn)

	r := &controlplane.CertRenewer{
		AgentID:     "agent-e2e",
		CertPath:    certPath,
		KeyPath:     keyPath,
		BundlePath:  bundlePath,
		Client:      rc,
		RenewBefore: 24 * time.Hour,
		Logger:      slog.Default(),
		TTLSeconds:  3600,
	}

	originalCert, _ := os.ReadFile(certPath)
	originalKey, _ := os.ReadFile(keyPath)
	r.Tick(context.Background())

	rotatedCert, _ := os.ReadFile(certPath)
	rotatedKey, _ := os.ReadFile(keyPath)
	if bytes.Equal(originalCert, rotatedCert) {
		t.Fatal("cert was not rotated")
	}
	if !bytes.Equal(originalKey, rotatedKey) {
		t.Fatal("private key changed during renewal — CSR mode must keep the key intact")
	}
	rotatedBundle, _ := os.ReadFile(bundlePath)
	if !bytes.Equal(rotatedBundle, ca.TrustBundlePEM()) {
		t.Fatal("bundle was not rolled over to the current trust bundle")
	}

	rotatedBlock, _ := pem.Decode(rotatedCert)
	rotatedX, _ := x509.ParseCertificate(rotatedBlock.Bytes)
	if err := ca.Revoke(rotatedX.SerialNumber.Text(16), "e2e revoke"); err != nil {
		t.Fatal(err)
	}

	clientTLS2 := clientTLS.Clone()
	clientTLS2.Certificates = []tls.Certificate{
		func() tls.Certificate {
			p, err := tls.X509KeyPair(rotatedCert, rotatedKey)
			if err != nil {
				t.Fatal(err)
			}
			return p
		}(),
	}
	conn2, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS2)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn2.Close() })
	rc2 := pb.NewControlPlaneClient(conn2)
	_, err = rc2.RenewCert(context.Background(), &pb.RenewCertRequest{AgentId: "agent-e2e"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for revoked, got %v", err)
	}
}

func TestE2E_GRPCRenew_RateLimited(t *testing.T) {
	caDir := t.TempDir()
	ca, err := mca.Init(caDir, "spiffe://test.firefik/")
	if err != nil {
		t.Fatal(err)
	}

	srvCert, _ := ca.IssueServerCert(mca.ServerCertRequest{
		DNSNames:    []string{"localhost"},
		IPAddresses: []string{"127.0.0.1"},
		TTL:         time.Hour,
	})
	srvTLS, _ := tls.X509KeyPair(srvCert.CertPEM, srvCert.KeyPEM)
	agentCert, _ := ca.Issue(mca.IssueRequest{AgentID: "agent-rl", TTL: 10 * time.Minute})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcTLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvTLS},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.ClientCAPool(),
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return mca.VerifySPIFFEPeer("spiffe://test.firefik/")(rawCerts, nil)
		},
	}
	store := controlplane.NewMemoryStore()
	registry := controlplane.NewRegistryWithStore(slog.Default(), store)
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(grpcTLS)))
	t.Cleanup(func() { gs.Stop() })
	grpcSvc := &controlplane.GRPCServer{
		Registry:         registry,
		Logger:           slog.Default(),
		CA:               controlplane.MCAAdapter{CA: ca},
		TrustDomain:      "spiffe://test.firefik/",
		RenewWindow:      24 * time.Hour,
		MinRenewInterval: time.Hour,
	}
	pb.RegisterControlPlaneServer(gs, grpcSvc)
	go func() { _ = gs.Serve(listener) }()

	clientTLS := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: "localhost",
		RootCAs: func() *x509.CertPool {
			p := x509.NewCertPool()
			p.AppendCertsFromPEM(srvCert.CertPEM)
			return p
		}(),
		Certificates: []tls.Certificate{
			func() tls.Certificate {
				p, _ := tls.X509KeyPair(agentCert.CertPEM, agentCert.KeyPEM)
				return p
			}(),
		},
	}
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	rc := pb.NewControlPlaneClient(conn)

	if _, err := rc.RenewCert(context.Background(), &pb.RenewCertRequest{AgentId: "agent-rl"}); err != nil {
		t.Fatalf("first renew: %v", err)
	}
	_, err = rc.RenewCert(context.Background(), &pb.RenewCertRequest{AgentId: "agent-rl"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected ResourceExhausted on second renew, got %v", err)
	}
}
