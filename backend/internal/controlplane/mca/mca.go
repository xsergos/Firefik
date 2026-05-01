package mca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultRootTTL   = 10 * 365 * 24 * time.Hour
	defaultAgentTTL  = 720 * time.Hour
	rootCertFile     = "root.crt"
	rootKeyFile      = "root.key"
	issuingCertFile  = "issuing.crt"
	issuingKeyFile   = "issuing.key"
	caOrganization   = "firefik control plane"
	spiffePathPrefix = "/agent/"
)

type CA struct {
	StateDir    string
	TrustDomain string

	rootCert    *x509.Certificate
	rootKey     *ecdsa.PrivateKey
	issuingCert *x509.Certificate
	issuingKey  *ecdsa.PrivateKey
}

func Open(stateDir, trustDomain string) (*CA, error) {
	ca := &CA{StateDir: stateDir, TrustDomain: trustDomain}
	if err := ca.load(); err != nil {
		return nil, err
	}
	return ca, nil
}

func Init(stateDir, trustDomain string) (*CA, error) {
	if trustDomain == "" {
		trustDomain = "firefik.local"
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state-dir: %w", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, rootCertFile)); err == nil {
		return Open(stateDir, trustDomain)
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("root key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	rootTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{caOrganization},
			CommonName:   "firefik root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour).UTC(),
		NotAfter:              time.Now().Add(defaultRootTTL).UTC(),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("root sign: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, fmt.Errorf("root parse: %w", err)
	}

	issuingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("issuing key: %w", err)
	}
	issuingSerial, err := randSerial()
	if err != nil {
		return nil, err
	}
	issuingTmpl := &x509.Certificate{
		SerialNumber: issuingSerial,
		Subject: pkix.Name{
			Organization: []string{caOrganization},
			CommonName:   "firefik issuing CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour).UTC(),
		NotAfter:              time.Now().Add(defaultRootTTL).UTC(),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	issuingDER, err := x509.CreateCertificate(rand.Reader, issuingTmpl, rootCert, &issuingKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("issuing sign: %w", err)
	}
	issuingCert, err := x509.ParseCertificate(issuingDER)
	if err != nil {
		return nil, fmt.Errorf("issuing parse: %w", err)
	}

	if err := writeCert(filepath.Join(stateDir, rootCertFile), rootDER); err != nil {
		return nil, err
	}
	if err := writeKey(filepath.Join(stateDir, rootKeyFile), rootKey); err != nil {
		return nil, err
	}
	if err := writeCert(filepath.Join(stateDir, issuingCertFile), issuingDER); err != nil {
		return nil, err
	}
	if err := writeKey(filepath.Join(stateDir, issuingKeyFile), issuingKey); err != nil {
		return nil, err
	}

	return &CA{
		StateDir:    stateDir,
		TrustDomain: trustDomain,
		rootCert:    rootCert,
		rootKey:     rootKey,
		issuingCert: issuingCert,
		issuingKey:  issuingKey,
	}, nil
}

func (c *CA) load() error {
	rootCert, err := readCert(filepath.Join(c.StateDir, rootCertFile))
	if err != nil {
		return fmt.Errorf("root cert: %w", err)
	}
	rootKey, err := readKey(filepath.Join(c.StateDir, rootKeyFile))
	if err != nil {
		return fmt.Errorf("root key: %w", err)
	}
	issuingCert, err := readCert(filepath.Join(c.StateDir, issuingCertFile))
	if err != nil {
		return fmt.Errorf("issuing cert: %w", err)
	}
	issuingKey, err := readKey(filepath.Join(c.StateDir, issuingKeyFile))
	if err != nil {
		return fmt.Errorf("issuing key: %w", err)
	}
	c.rootCert = rootCert
	c.rootKey = rootKey
	c.issuingCert = issuingCert
	c.issuingKey = issuingKey
	return nil
}

func (c *CA) RootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.rootCert.Raw})
}

func (c *CA) TrustBundlePEM() []byte {
	var out []byte
	out = append(out, c.RootPEM()...)
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.issuingCert.Raw})...)
	return out
}

type IssueRequest struct {
	AgentID   string
	TTL       time.Duration
	PublicKey interface{}
}

type IssueResult struct {
	CertPEM   []byte
	BundlePEM []byte
	KeyPEM    []byte
	SerialHex string
	NotAfter  time.Time
	SPIFFEURI string
}

func (c *CA) Issue(req IssueRequest) (*IssueResult, error) {
	if req.AgentID == "" {
		return nil, errors.New("agent-id required")
	}
	if req.TTL == 0 {
		req.TTL = defaultAgentTTL
	}
	if req.TTL > 90*24*time.Hour {
		req.TTL = 90 * 24 * time.Hour
	}
	var keyPEM []byte
	pub := req.PublicKey
	if pub == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("agent key: %w", err)
		}
		pub = &key.PublicKey
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshal key: %w", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}

	spiffeURI, err := c.spiffeURI(req.AgentID)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{caOrganization},
			CommonName:   req.AgentID,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour).UTC(),
		NotAfter:    time.Now().Add(req.TTL).UTC(),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:        []*url.URL{spiffeURI},
		DNSNames:    []string{req.AgentID},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.issuingCert, pub, c.issuingKey)
	if err != nil {
		return nil, fmt.Errorf("sign agent: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse agent: %w", err)
	}
	return &IssueResult{
		CertPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		BundlePEM: c.TrustBundlePEM(),
		KeyPEM:    keyPEM,
		SerialHex: cert.SerialNumber.Text(16),
		NotAfter:  cert.NotAfter,
		SPIFFEURI: spiffeURI.String(),
	}, nil
}

func (c *CA) spiffeURI(agentID string) (*url.URL, error) {
	domain := strings.TrimPrefix(c.TrustDomain, "spiffe://")
	domain = strings.TrimSuffix(domain, "/")
	if domain == "" {
		return nil, errors.New("empty trust domain")
	}
	u := &url.URL{Scheme: "spiffe", Host: domain, Path: spiffePathPrefix + agentID}
	return u, nil
}

func (c *CA) ClientCAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.rootCert)
	pool.AddCert(c.issuingCert)
	return pool
}

func (c *CA) RootCert() *x509.Certificate    { return c.rootCert }
func (c *CA) IssuingCert() *x509.Certificate { return c.issuingCert }

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func readCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func writeCert(path string, der []byte) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return os.WriteFile(path, pemBytes, 0o644)
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return os.WriteFile(path, pemBytes, 0o600)
}

func VerifySPIFFEPeer(trustDomain string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	domain := strings.TrimPrefix(trustDomain, "spiffe://")
	domain = strings.TrimSuffix(domain, "/")
	prefix := "spiffe://" + domain + "/"
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if trustDomain == "" {
			return nil
		}
		if len(rawCerts) == 0 {
			return errors.New("no peer cert")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse peer cert: %w", err)
		}
		for _, u := range cert.URIs {
			if u == nil {
				continue
			}
			if strings.HasPrefix(u.String(), prefix) {
				return nil
			}
		}
		return fmt.Errorf("peer has no SPIFFE SAN under %s", prefix)
	}
}
