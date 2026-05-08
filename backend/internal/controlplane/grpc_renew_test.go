package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/url"
	"testing"
	"time"

	pb "firefik/internal/controlplane/gen/controlplanev1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type fakeCA struct {
	revoked map[string]bool
	calls   int
}

func newFakeCA() *fakeCA { return &fakeCA{revoked: map[string]bool{}} }

func (f *fakeCA) Issue(req CAIssueRequest) (*CAIssueResult, error) {
	f.calls++
	return &CAIssueResult{
		CertPEM:   []byte("CERT"),
		KeyPEM:    []byte("KEY"),
		BundlePEM: []byte("BUNDLE"),
		SerialHex: "11ff",
		NotAfter:  time.Now().Add(time.Hour),
		SPIFFEURI: "spiffe://test.firefik/agent/" + req.AgentID,
	}, nil
}

func (f *fakeCA) IssueFromCSR(_ []byte, agentID string, _ time.Duration) (*CAIssueResult, error) {
	f.calls++
	return &CAIssueResult{
		CertPEM:   []byte("CERT"),
		BundlePEM: []byte("BUNDLE"),
		SerialHex: "22ff",
		NotAfter:  time.Now().Add(time.Hour),
		SPIFFEURI: "spiffe://test.firefik/agent/" + agentID,
	}, nil
}

func (f *fakeCA) IsRevoked(serial string) bool { return f.revoked[serial] }

func (f *fakeCA) TrustBundlePEM() []byte { return []byte("BUNDLE") }

func makePeerCert(t *testing.T, agentID string, ttl time.Duration) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://test.firefik/agent/" + agentID)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: agentID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(ttl),
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, priv
}

func ctxWithPeerCert(cert *x509.Certificate) context.Context {
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	tlsInfo := credentials.TLSInfo{State: state}
	p := &peer.Peer{AuthInfo: tlsInfo}
	return peer.NewContext(context.Background(), p)
}

func newGRPCRenewServer(ca CertAuthority) *GRPCServer {
	return &GRPCServer{
		Registry:         &Registry{store: NewMemoryStore()},
		Logger:           slog.Default(),
		CA:               ca,
		TrustDomain:      "spiffe://test.firefik/",
		RenewWindow:      24 * time.Hour,
		MinRenewInterval: time.Minute,
	}
}

func TestRenewCert_NoPeerCert(t *testing.T) {
	srv := newGRPCRenewServer(newFakeCA())
	_, err := srv.RenewCert(context.Background(), &pb.RenewCertRequest{AgentId: "agent-a"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestRenewCert_AgentIDMismatch(t *testing.T) {
	srv := newGRPCRenewServer(newFakeCA())
	cert, _ := makePeerCert(t, "agent-a", time.Hour)
	_, err := srv.RenewCert(ctxWithPeerCert(cert), &pb.RenewCertRequest{AgentId: "agent-b"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestRenewCert_OutsideRenewalWindow(t *testing.T) {
	srv := newGRPCRenewServer(newFakeCA())
	srv.RenewWindow = 24 * time.Hour
	cert, _ := makePeerCert(t, "agent-a", 10*24*time.Hour)
	_, err := srv.RenewCert(ctxWithPeerCert(cert), &pb.RenewCertRequest{AgentId: "agent-a"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
}

func TestRenewCert_Revoked(t *testing.T) {
	ca := newFakeCA()
	srv := newGRPCRenewServer(ca)
	cert, _ := makePeerCert(t, "agent-a", time.Hour)
	ca.revoked[cert.SerialNumber.Text(16)] = true
	_, err := srv.RenewCert(ctxWithPeerCert(cert), &pb.RenewCertRequest{AgentId: "agent-a"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for revoked, got %v", err)
	}
}

func TestRenewCert_HappyPath_ServerKeygen(t *testing.T) {
	ca := newFakeCA()
	srv := newGRPCRenewServer(ca)
	cert, _ := makePeerCert(t, "agent-a", time.Hour)
	resp, err := srv.RenewCert(ctxWithPeerCert(cert), &pb.RenewCertRequest{AgentId: "agent-a"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(resp.GetCertPem()) != "CERT" || string(resp.GetKeyPem()) != "KEY" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if ca.calls != 1 {
		t.Fatalf("expected 1 issue call, got %d", ca.calls)
	}
}

func TestRenewCert_HappyPath_CSR(t *testing.T) {
	ca := newFakeCA()
	srv := newGRPCRenewServer(ca)
	cert, priv := makePeerCert(t, "agent-a", time.Hour)

	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent-a"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	resp, err := srv.RenewCert(ctxWithPeerCert(cert), &pb.RenewCertRequest{
		AgentId: "agent-a", CsrPem: csrPEM,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(resp.GetKeyPem()) != 0 {
		t.Fatal("CSR-mode response must not contain a private key")
	}
}

func TestRenewCert_CSRPubKeyMismatch(t *testing.T) {
	ca := newFakeCA()
	srv := newGRPCRenewServer(ca)
	cert, _ := makePeerCert(t, "agent-a", time.Hour)

	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent-a"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	_, err = srv.RenewCert(ctxWithPeerCert(cert), &pb.RenewCertRequest{
		AgentId: "agent-a", CsrPem: csrPEM,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestRenewCert_RateLimited(t *testing.T) {
	ca := newFakeCA()
	srv := newGRPCRenewServer(ca)
	srv.MinRenewInterval = time.Hour
	cert, _ := makePeerCert(t, "agent-a", time.Hour)

	if _, err := srv.RenewCert(ctxWithPeerCert(cert), &pb.RenewCertRequest{AgentId: "agent-a"}); err != nil {
		t.Fatalf("first renew: %v", err)
	}

	cert2, _ := makePeerCert(t, "agent-a", time.Hour)
	srv2 := newGRPCRenewServer(ca)
	srv2.MinRenewInterval = time.Hour
	srv2.Registry = srv.Registry
	if err := srv.Registry.store.RecordCertRenew(context.Background(),
		cert2.SerialNumber.Text(16), "agent-a", time.Now()); err != nil {
		t.Fatal(err)
	}
	_, err := srv2.RenewCert(ctxWithPeerCert(cert2), &pb.RenewCertRequest{AgentId: "agent-a"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected ResourceExhausted, got %v", err)
	}
}

func TestRenewCert_TrustDomainMismatch(t *testing.T) {
	ca := newFakeCA()
	srv := newGRPCRenewServer(ca)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uri, _ := url.Parse("spiffe://other.domain/agent/agent-a")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "agent-a"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{uri},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	parsed, _ := x509.ParseCertificate(der)
	_, err := srv.RenewCert(ctxWithPeerCert(parsed), &pb.RenewCertRequest{AgentId: "agent-a"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for foreign trust domain, got %v", err)
	}
}

func TestRenewCert_NoCAConfigured(t *testing.T) {
	srv := &GRPCServer{Registry: &Registry{store: NewMemoryStore()}, Logger: slog.Default()}
	cert, _ := makePeerCert(t, "agent-a", time.Hour)
	_, err := srv.RenewCert(ctxWithPeerCert(cert), &pb.RenewCertRequest{AgentId: "agent-a"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
}
