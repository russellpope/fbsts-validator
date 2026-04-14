package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// NewHTTPClient builds an *http.Client configured for FlashBlade environments.
// If insecure is true, TLS certificate verification is skipped.
// If caCertPath is non-empty, the PEM file is added to the trust pool.
func NewHTTPClient(insecure bool, caCertPath string) (*http.Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure,
	}

	if caCertPath != "" && !insecure {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("reading CA certificate %s: %w", caCertPath, err)
		}

		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caCertPath)
		}
		tlsConfig.RootCAs = pool
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}, nil
}
