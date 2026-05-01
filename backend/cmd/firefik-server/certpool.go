package main

import (
	"crypto/x509"
	"fmt"
)

func readCertPool(pem []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in client-ca bundle")
	}
	return pool, nil
}
