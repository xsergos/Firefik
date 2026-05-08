package controlplane

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

type keyPairLoader struct {
	certPath string
	keyPath  string

	mu        sync.Mutex
	cached    *tls.Certificate
	certMtime time.Time
	keyMtime  time.Time
}

func newKeyPairLoader(certPath, keyPath string) *keyPairLoader {
	return &keyPairLoader{certPath: certPath, keyPath: keyPath}
}

func (l *keyPairLoader) getClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
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
