package controlplane

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

type KeypairLoader struct {
	certPath string
	keyPath  string

	mu        sync.Mutex
	cached    *tls.Certificate
	certMtime time.Time
	keyMtime  time.Time
}

func newKeyPairLoader(certPath, keyPath string) *KeypairLoader {
	return &KeypairLoader{certPath: certPath, keyPath: keyPath}
}

func NewKeypairLoader(certPath, keyPath string) *KeypairLoader {
	return newKeyPairLoader(certPath, keyPath)
}

func (l *KeypairLoader) GetServerCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return l.load()
}

func (l *KeypairLoader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return l.load()
}

func (l *KeypairLoader) load() (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	certInfo, certErr := os.Stat(l.certPath)
	keyInfo, keyErr := os.Stat(l.keyPath)
	if certErr == nil && keyErr == nil && l.cached != nil &&
		certInfo.ModTime().Equal(l.certMtime) &&
		keyInfo.ModTime().Equal(l.keyMtime) {
		return l.cached, nil
	}

	pair, err := tls.LoadX509KeyPair(l.certPath, l.keyPath)
	if err != nil {
		if l.cached != nil {
			return l.cached, nil
		}
		return nil, err
	}
	l.cached = &pair
	if certInfo != nil {
		l.certMtime = certInfo.ModTime()
	}
	if keyInfo != nil {
		l.keyMtime = keyInfo.ModTime()
	}
	return l.cached, nil
}
