package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"firefik/internal/controlplane/mca"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func writeCAPEM(t *testing.T, dir string) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCertAndKey(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, pemCert, 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, pemKey, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestBuildTLSAllEmpty(t *testing.T) {
	cfg, err := buildTLS("", "", "", "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil tls config when nothing set")
	}
}

func TestBuildTLSCertWithoutKey(t *testing.T) {
	if _, err := buildTLS("cert.pem", "", "", ""); err == nil {
		t.Fatal("expected error")
	}
	if _, err := buildTLS("", "key.pem", "", ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildTLSCertAndKey(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeCertAndKey(t, dir)
	cfg, err := buildTLS(certPath, keyPath, "", "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected tls config")
	}
}

func TestBuildTLSWithClientCA(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeCertAndKey(t, dir)
	caPath := writeCAPEM(t, dir)
	cfg, err := buildTLS(certPath, keyPath, caPath, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if cfg.ClientCAs == nil {
		t.Errorf("expected ClientCAs set")
	}
}

func TestBuildTLSMissingClientCA(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeCertAndKey(t, dir)
	if _, err := buildTLS(certPath, keyPath, "/no/such/file", ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildTLSInvalidCAPEM(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeCertAndKey(t, dir)
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildTLS(certPath, keyPath, bad, ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildTLSWithTrustDomain(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeCertAndKey(t, dir)
	caPath := writeCAPEM(t, dir)
	cfg, err := buildTLS(certPath, keyPath, caPath, "spiffe://test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Error("expected VerifyPeerCertificate set when trust-domain present")
	}
	err = cfg.VerifyPeerCertificate(nil, nil)
	if err == nil {
		t.Errorf("expected error from empty rawCerts")
	}
}

func TestCheckBearerNoMetadata(t *testing.T) {
	if err := checkBearer(context.Background(), "tok"); err == nil {
		t.Fatal("expected error")
	}
}

func TestCheckBearerNoAuthHeader(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{})
	if err := checkBearer(ctx, "tok"); err == nil {
		t.Fatal("expected error")
	}
}

func TestCheckBearerWrong(t *testing.T) {
	md := metadata.New(map[string]string{"authorization": "Bearer wrong"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if err := checkBearer(ctx, "tok"); err == nil {
		t.Fatal("expected error")
	}
}

func TestCheckBearerOK(t *testing.T) {
	md := metadata.New(map[string]string{"authorization": "Bearer tok"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if err := checkBearer(ctx, "tok"); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestUnaryAuthOK(t *testing.T) {
	md := metadata.New(map[string]string{"authorization": "Bearer x"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	called := false
	handler := func(ctx context.Context, req any) (any, error) { called = true; return "ok", nil }
	resp, err := unaryAuth("x")(ctx, nil, nil, handler)
	if err != nil || !called || resp != "ok" {
		t.Errorf("unexpected: err=%v called=%v resp=%v", err, called, resp)
	}
}

func TestUnaryAuthBlocks(t *testing.T) {
	if _, err := unaryAuth("x")(context.Background(), nil, nil, nil); err == nil {
		t.Fatal("expected error")
	}
}

type fakeStream struct {
	ctx context.Context
}

func (f *fakeStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeStream) SetTrailer(metadata.MD)      {}
func (f *fakeStream) Context() context.Context     { return f.ctx }
func (f *fakeStream) SendMsg(any) error            { return nil }
func (f *fakeStream) RecvMsg(any) error            { return nil }

func TestStreamAuthOK(t *testing.T) {
	md := metadata.New(map[string]string{"authorization": "Bearer x"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	called := false
	handler := grpc.StreamHandler(func(srv any, ss grpc.ServerStream) error { called = true; return nil })
	if err := streamAuth("x")(nil, &fakeStream{ctx: ctx}, nil, handler); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !called {
		t.Error("handler not called")
	}
}

func TestStreamAuthBlocks(t *testing.T) {
	handler := grpc.StreamHandler(func(srv any, ss grpc.ServerStream) error { return nil })
	if err := streamAuth("x")(nil, &fakeStream{ctx: context.Background()}, nil, handler); err == nil {
		t.Fatal("expected error")
	}
}

func TestWrappedServerStreamContext(t *testing.T) {
	type kctx struct{}
	parent := context.Background()
	ctx := context.WithValue(parent, kctx{}, "v")
	ws := &wrappedServerStream{ServerStream: &fakeStream{ctx: parent}, ctx: ctx}
	got := ws.Context()
	if got != ctx {
		t.Errorf("Context() should return wrapped ctx")
	}
	if v, _ := got.Value(kctx{}).(string); v != "v" {
		t.Errorf("expected wrapped value, got %q", v)
	}
}

func TestDefaultDBPathDefault(t *testing.T) {
	t.Setenv("FIREFIK_CP_DB", "")
	if got := defaultDBPath(); got == "" {
		t.Errorf("expected non-empty default")
	}
}

func TestDefaultDBPathFromEnv(t *testing.T) {
	t.Setenv("FIREFIK_CP_DB", "/tmp/mydb")
	if got := defaultDBPath(); got != "/tmp/mydb" {
		t.Errorf("got %q", got)
	}
}

func TestTrustDomainFromEnvDefault(t *testing.T) {
	t.Setenv("FIREFIK_CP_TRUST_DOMAIN", "")
	if got := trustDomainFromEnv(); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestTrustDomainFromEnvSet(t *testing.T) {
	t.Setenv("FIREFIK_CP_TRUST_DOMAIN", "spiffe://x")
	if got := trustDomainFromEnv(); got != "spiffe://x" {
		t.Errorf("got %q", got)
	}
}

func TestDefaultCAStateDirDefault(t *testing.T) {
	t.Setenv("FIREFIK_CP_CA_DIR", "")
	if got := defaultCAStateDir(); got == "" {
		t.Errorf("expected non-empty default")
	}
}

func TestDefaultCAStateDirFromEnv(t *testing.T) {
	t.Setenv("FIREFIK_CP_CA_DIR", "/x/y")
	if got := defaultCAStateDir(); got != "/x/y" {
		t.Errorf("got %q", got)
	}
}

func TestReadCertPoolValid(t *testing.T) {
	dir := t.TempDir()
	p := writeCAPEM(t, dir)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := readCertPool(data)
	if err != nil || pool == nil {
		t.Errorf("err=%v pool=%v", err, pool)
	}
}

func TestReadCertPoolInvalid(t *testing.T) {
	if _, err := readCertPool([]byte("not pem")); err == nil {
		t.Fatal("expected error")
	}
}

func TestMakeEnrollHandlerMethodNotAllowed(t *testing.T) {
	dir := t.TempDir()
	ca, err := mca.Init(dir, "spiffe://x")
	if err != nil {
		t.Fatal(err)
	}
	h := makeEnrollHandler(ca, "", slog.Default())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/enroll", nil)
	h(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("code = %d", rec.Code)
	}
}

func TestMakeEnrollHandlerMissingToken(t *testing.T) {
	dir := t.TempDir()
	ca, err := mca.Init(dir, "spiffe://x")
	if err != nil {
		t.Fatal(err)
	}
	h := makeEnrollHandler(ca, "secret", slog.Default())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{"agent_id":"a"}`))
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code = %d", rec.Code)
	}
}

func TestMakeEnrollHandlerBadJSON(t *testing.T) {
	dir := t.TempDir()
	ca, err := mca.Init(dir, "spiffe://x")
	if err != nil {
		t.Fatal(err)
	}
	h := makeEnrollHandler(ca, "", slog.Default())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`not json`))
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code = %d", rec.Code)
	}
}

func TestMakeEnrollHandlerMissingAgentID(t *testing.T) {
	dir := t.TempDir()
	ca, err := mca.Init(dir, "spiffe://x")
	if err != nil {
		t.Fatal(err)
	}
	h := makeEnrollHandler(ca, "", slog.Default())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{}`))
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("code = %d", rec.Code)
	}
}

func TestMakeEnrollHandlerSuccess(t *testing.T) {
	dir := t.TempDir()
	ca, err := mca.Init(dir, "spiffe://x")
	if err != nil {
		t.Fatal(err)
	}
	h := makeEnrollHandler(ca, "", slog.Default())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{"agent_id":"a","ttl_seconds":3600}`))
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code = %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["cert_pem"] == "" {
		t.Errorf("expected cert_pem in response")
	}
}

func TestMakeEnrollHandlerWithTokenOK(t *testing.T) {
	dir := t.TempDir()
	ca, err := mca.Init(dir, "spiffe://x")
	if err != nil {
		t.Fatal(err)
	}
	h := makeEnrollHandler(ca, "secret", slog.Default())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(`{"agent_id":"a"}`))
	req.Header.Set("Authorization", "Bearer secret")
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("code = %d", rec.Code)
	}
}
