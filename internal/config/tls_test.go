package config

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestNewHTTPClientDefault(t *testing.T) {
	client, err := NewHTTPClient(false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("client should not be nil")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport should be *http.Transport")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false by default")
	}
}

func TestNewHTTPClientInsecure(t *testing.T) {
	client, err := NewHTTPClient(true, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := client.Transport.(*http.Transport)
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true when insecure=true")
	}
}

func TestNewHTTPClientCustomCA(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")

	pemData := `-----BEGIN CERTIFICATE-----
MIIBPDCB5KADAgECAgEBMAoGCCqGSM49BAMCMA8xDTALBgNVBAoTBFRlc3QwHhcN
MjYwNDE0MjIyOTE4WhcNMzYwNDExMjIyOTE4WjAPMQ0wCwYDVQQKEwRUZXN0MFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExigcXUe1fKsp27B29zgd7Uh8wbW6gL9v
MiIskk5u+3rxyAw+M3YLZZy9RoKPtwTB9h1YwxxkeY3Ll0z2CSaTiaMxMC8wDgYD
VR0PAQH/BAQDAgIEMB0GA1UdDgQWBBQ3uW+R7jM/ZBWoQqPn9HZlVVcCgTAKBggq
hkjOPQQDAgNHADBEAiAYvXFlokArzbD/vc8aumAYYGKXi4vJG2GTNt8d0E22YgIg
AtQDZQAKBLo7BPnU8BED83iP4LE8JCI6OYuONbNd1tI=
-----END CERTIFICATE-----`
	os.WriteFile(caPath, []byte(pemData), 0644)

	client, err := NewHTTPClient(false, caPath)
	if err != nil {
		t.Fatalf("unexpected error with custom CA: %v", err)
	}
	if client == nil {
		t.Fatal("client should not be nil")
	}
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("RootCAs should be set when ca_cert is provided")
	}
}

func TestNewHTTPClientBadCAPath(t *testing.T) {
	_, err := NewHTTPClient(false, "/nonexistent/ca.pem")
	if err == nil {
		t.Error("expected error for nonexistent CA file")
	}
}
