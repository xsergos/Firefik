package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "firefik/internal/controlplane/gen/controlplanev1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCidrsToStrings_Empty(t *testing.T) {
	if got := cidrsToStrings(nil); len(got) != 0 {
		t.Errorf("nil → %v", got)
	}
	if got := cidrsToStrings([]net.IPNet{}); len(got) != 0 {
		t.Errorf("empty → %v", got)
	}
}

func TestCidrsToStrings_Mix(t *testing.T) {
	_, n1, _ := net.ParseCIDR("10.0.0.0/8")
	_, n2, _ := net.ParseCIDR("192.168.1.0/24")
	got := cidrsToStrings([]net.IPNet{*n1, *n2})
	if len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != "192.168.1.0/24" {
		t.Errorf("got %v", got)
	}
}

func TestNormaliseDefaultPolicy(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{"drop", "DROP"},
		{" Drop ", "DROP"},
		{"ACCEPT", "ACCEPT"},
		{"return", "RETURN"},
		{"", "RETURN"},
		{"junk", "RETURN"},
	}
	for _, c := range cases {
		if got := normaliseDefaultPolicy(c.in); got != c.out {
			t.Errorf("normaliseDefaultPolicy(%q)=%q want %q", c.in, got, c.out)
		}
	}
}

func TestNonEmptyOr(t *testing.T) {
	if got := nonEmptyOr("", "fallback"); got != "fallback" {
		t.Errorf("empty → %q", got)
	}
	if got := nonEmptyOr("real", "fallback"); got != "real" {
		t.Errorf("non-empty → %q", got)
	}
}

func TestShortSHA(t *testing.T) {
	if got := shortSHA(""); got != "" {
		t.Errorf("empty → %q", got)
	}
	if got := shortSHA("abc"); got != "abc" {
		t.Errorf("short → %q", got)
	}
	long := "abcdef0123456789xyz"
	if got := shortSHA(long); got != "abcdef012345" || len(got) != 12 {
		t.Errorf("long → %q", got)
	}
}

func TestBoolInt(t *testing.T) {
	if boolInt(true) != 1 {
		t.Errorf("true → %d", boolInt(true))
	}
	if boolInt(false) != 0 {
		t.Errorf("false → %d", boolInt(false))
	}
}

func TestSortAgentTokens(t *testing.T) {
	now := time.Now()
	in := []AgentToken{
		{ID: "a", IssuedAt: now.Add(-3 * time.Hour)},
		{ID: "b", IssuedAt: now.Add(-1 * time.Hour)},
		{ID: "c", IssuedAt: now.Add(-2 * time.Hour)},
	}
	sortAgentTokens(in)
	if in[0].ID != "b" || in[1].ID != "c" || in[2].ID != "a" {
		t.Errorf("sorted desc by IssuedAt: %v", in)
	}
}

func TestWriteFileAtomic_EmptyPath(t *testing.T) {
	if err := writeFileAtomic("", []byte("x"), 0o600); err == nil {
		t.Fatal("empty path should error")
	}
}

func TestWriteFileAtomic_Success(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.txt")
	if err := writeFileAtomic(p, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("content: %q", got)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("tmp should be removed/renamed; stat err=%v", err)
	}
}

func TestWriteFileAtomic_BadDir(t *testing.T) {
	p := filepath.Join(t.TempDir(), "does", "not", "exist", "f.txt")
	if err := writeFileAtomic(p, []byte("x"), 0o600); err == nil {
		t.Fatal("expected error for missing parent dir")
	}
}

func TestParsePrivateKeyPEM_NoPEM(t *testing.T) {
	if _, err := parsePrivateKeyPEM([]byte("not a pem")); err == nil {
		t.Fatal("expected error")
	}
}

func TestParsePrivateKeyPEM_ECPrivateKey(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	signer, err := parsePrivateKeyPEM(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if signer == nil {
		t.Fatal("nil signer")
	}
}

func TestParsePrivateKeyPEM_RSAPrivateKey(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	if _, err := parsePrivateKeyPEM(encoded); err != nil {
		t.Fatalf("parse: %v", err)
	}
}

func TestParsePrivateKeyPEM_PKCS8Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := parsePrivateKeyPEM(encoded); err != nil {
		t.Fatalf("parse: %v", err)
	}
}

func TestParsePrivateKeyPEM_UnsupportedType(t *testing.T) {
	encoded := pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte("garbage")})
	if _, err := parsePrivateKeyPEM(encoded); err == nil {
		t.Fatal("expected error")
	}
}

func TestParsePrivateKeyPEM_CorruptECKey(t *testing.T) {
	encoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("corrupt")})
	if _, err := parsePrivateKeyPEM(encoded); err == nil {
		t.Fatal("expected error")
	}
}

func TestParsePrivateKeyPEM_CorruptRSAKey(t *testing.T) {
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("corrupt")})
	if _, err := parsePrivateKeyPEM(encoded); err == nil {
		t.Fatal("expected error")
	}
}

func TestParsePrivateKeyPEM_CorruptPKCS8(t *testing.T) {
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("corrupt")})
	if _, err := parsePrivateKeyPEM(encoded); err == nil {
		t.Fatal("expected error")
	}
}

func TestToNativeAutogenProposals_Nil(t *testing.T) {
	if got := toNativeAutogenProposals(nil); got != nil {
		t.Errorf("nil input: %v", got)
	}
	if got := toNativeAutogenProposals(&pb.AutogenProposals{Agent: nil}); got != nil {
		t.Errorf("nil agent: %v", got)
	}
}

func TestToNativeAutogenProposals_HappyPath(t *testing.T) {
	at := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	in := &pb.AutogenProposals{
		Agent: &pb.AgentIdentity{InstanceId: "agent-1"},
		Proposals: []*pb.AutogenProposal{
			{
				ContainerId: "c1",
				Ports:       []uint32{80, 443},
				Peers:       []string{"10.0.0.0/8"},
				ObservedFor: "1h",
				Confidence:  "high",
			},
			nil,
			{ContainerId: "c2"},
		},
		At: timestamppb.New(at),
	}
	out := toNativeAutogenProposals(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 proposals (nil skipped), got %d", len(out))
	}
	if out[0].AgentID != "agent-1" || out[0].ContainerID != "c1" || len(out[0].Ports) != 2 || out[0].Confidence != "high" {
		t.Errorf("first proposal: %+v", out[0])
	}
	if !out[0].UpdatedAt.Equal(at) {
		t.Errorf("at: %v want %v", out[0].UpdatedAt, at)
	}
}

func TestRegistry_RecordProposals_NilStoreNoop(t *testing.T) {
	r := &Registry{}
	r.RecordProposals([]AutogenProposal{{AgentID: "a1", ContainerID: "c1"}})
}

func TestRegistry_RecordProposals_EmptyNoop(t *testing.T) {
	r := &Registry{}
	r.RecordProposals(nil)
	r.RecordProposals([]AutogenProposal{})
}

func TestGRPCServer_EmitAudit_NoSinkNoop(t *testing.T) {
	srv := &GRPCServer{}
	srv.emitAudit("x", map[string]string{"k": "v"})
}

func TestGRPCServer_EmitAudit_WithSink(t *testing.T) {
	sink := &recordingAudit{}
	srv := &GRPCServer{Audit: sink}
	srv.emitAudit("renew", map[string]string{"agent_id": "a1"})
	if len(sink.events) != 1 || sink.events[0].action != "renew" {
		t.Errorf("events: %+v", sink.events)
	}
	if sink.events[0].meta["agent_id"] != "a1" {
		t.Errorf("meta: %v", sink.events[0].meta)
	}
}

func TestWithBearerValidated_AllowsAuthoriseWithoutToken(t *testing.T) {
	srv := &GRPCServer{Token: "secret"}
	ctx := WithBearerValidated(context.Background())
	if err := srv.authorise(ctx); err != nil {
		t.Errorf("validated ctx should pass: %v", err)
	}
}

func TestWithBearerValidated_PlainCtxFailsWhenTokenSet(t *testing.T) {
	srv := &GRPCServer{Token: "secret"}
	if err := srv.authorise(context.Background()); err == nil {
		t.Error("plain ctx should fail when token set")
	}
}

func TestSessionStore_RunJanitor_ExitsOnContextCancel(t *testing.T) {
	s := NewSessionStore()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.RunJanitor(ctx, 10*time.Millisecond)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunJanitor did not return after cancel")
	}
}

func TestSessionStore_RunJanitor_ZeroIntervalDefaults(t *testing.T) {
	s := NewSessionStore()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.RunJanitor(ctx, 0)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunJanitor did not return after cancel (interval=0)")
	}
}

func TestSessionStore_RunJanitor_SweepsOnTick(t *testing.T) {
	s := NewSessionStore().WithTTL(time.Millisecond, time.Nanosecond)
	sess, err := s.Create("u1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	go s.RunJanitor(ctx, 10*time.Millisecond)
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := s.Touch(sess.ID); err != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("session not swept")
}

func TestToNativeAutogenProposals_FallbackAtIsNow(t *testing.T) {
	before := time.Now().UTC()
	out := toNativeAutogenProposals(&pb.AutogenProposals{
		Agent:     &pb.AgentIdentity{InstanceId: "agent-1"},
		Proposals: []*pb.AutogenProposal{{ContainerId: "c1"}},
	})
	after := time.Now().UTC()
	if len(out) != 1 {
		t.Fatalf("len: %d", len(out))
	}
	if out[0].UpdatedAt.Before(before) || out[0].UpdatedAt.After(after) {
		t.Errorf("UpdatedAt %v not in [%v, %v]", out[0].UpdatedAt, before, after)
	}
}
