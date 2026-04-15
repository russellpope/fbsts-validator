package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestOktaAuthenticatorName(t *testing.T) {
	a := NewOktaAuthenticator("https://example.okta.com", "client123", []string{"openid"}, http.DefaultClient)
	if got := a.Name(); got != "okta" {
		t.Fatalf("Name() = %q, want %q", got, "okta")
	}
}

func TestOktaDiscover(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"device_authorization_endpoint": "https://example.okta.com/v1/device/authorize",
			"token_endpoint":                "https://example.okta.com/v1/token",
		})
	}))
	defer srv.Close()

	a := NewOktaAuthenticator(srv.URL, "client123", []string{"openid"}, srv.Client())
	endpoints, err := a.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error: %v", err)
	}
	if endpoints.DeviceAuthorizationEndpoint != "https://example.okta.com/v1/device/authorize" {
		t.Errorf("DeviceAuthorizationEndpoint = %q, unexpected", endpoints.DeviceAuthorizationEndpoint)
	}
	if endpoints.TokenEndpoint != "https://example.okta.com/v1/token" {
		t.Errorf("TokenEndpoint = %q, unexpected", endpoints.TokenEndpoint)
	}
}

func TestOktaDiscoverBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := NewOktaAuthenticator(srv.URL, "client123", []string{"openid"}, srv.Client())
	_, err := a.Discover(context.Background())
	if err == nil {
		t.Fatal("Discover() expected error for 500 response, got nil")
	}
}

func TestOktaStartDeviceAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               "dev-code-abc",
			"user_code":                 "ABCD-1234",
			"verification_uri":          "https://example.okta.com/activate",
			"verification_uri_complete": "https://example.okta.com/activate?user_code=ABCD-1234",
			"expires_in":                300,
			"interval":                  5,
		})
	}))
	defer srv.Close()

	endpoints := &OIDCEndpoints{
		DeviceAuthorizationEndpoint: srv.URL + "/device/authorize",
		TokenEndpoint:               srv.URL + "/token",
	}

	a := NewOktaAuthenticator(srv.URL, "client123", []string{"openid", "profile"}, srv.Client())
	resp, err := a.StartDeviceAuth(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("StartDeviceAuth() error: %v", err)
	}
	if resp.DeviceCode != "dev-code-abc" {
		t.Errorf("DeviceCode = %q, want %q", resp.DeviceCode, "dev-code-abc")
	}
	if resp.UserCode != "ABCD-1234" {
		t.Errorf("UserCode = %q, want %q", resp.UserCode, "ABCD-1234")
	}
	if resp.VerificationURI != "https://example.okta.com/activate" {
		t.Errorf("VerificationURI = %q, unexpected", resp.VerificationURI)
	}
	if resp.ExpiresIn != 300 {
		t.Errorf("ExpiresIn = %d, want 300", resp.ExpiresIn)
	}
	if resp.Interval != 5 {
		t.Errorf("Interval = %d, want 5", resp.Interval)
	}
}

func TestOktaPollForToken(t *testing.T) {
	var callCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")

		if n == 1 {
			// First call: authorization_pending
			json.NewEncoder(w).Encode(map[string]string{
				"error": "authorization_pending",
			})
			return
		}

		// Second call: success
		json.NewEncoder(w).Encode(map[string]string{
			"id_token":     "eyJ.id.token",
			"access_token": "eyJ.access.token",
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	endpoints := &OIDCEndpoints{
		DeviceAuthorizationEndpoint: srv.URL + "/device/authorize",
		TokenEndpoint:               srv.URL + "/token",
	}

	a := NewOktaAuthenticator(srv.URL, "client123", []string{"openid"}, srv.Client())

	tok, err := a.PollForToken(context.Background(), endpoints, "dev-code-xyz", 1)
	if err != nil {
		t.Fatalf("PollForToken() error: %v", err)
	}
	if tok.IDToken != "eyJ.id.token" {
		t.Errorf("IDToken = %q, want %q", tok.IDToken, "eyJ.id.token")
	}
	if tok.AccessToken != "eyJ.access.token" {
		t.Errorf("AccessToken = %q, want %q", tok.AccessToken, "eyJ.access.token")
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", tok.TokenType, "Bearer")
	}

	if n := atomic.LoadInt32(&callCount); n != 2 {
		t.Errorf("token endpoint called %d times, want 2", n)
	}
}

// Ensure OktaAuthenticator satisfies the IDPAuthenticator interface at compile time.
var _ IDPAuthenticator = (*OktaAuthenticator)(nil)

// suppress unused import warning in case json is only used indirectly
var _ = fmt.Sprintf
