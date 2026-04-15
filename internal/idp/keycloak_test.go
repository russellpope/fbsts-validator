package idp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestKeycloakAuthenticatorName(t *testing.T) {
	kc := NewKeycloakAuthenticator("https://keycloak.example.com/realms/my-realm", "my-client", []string{"openid"}, http.DefaultClient)
	if kc.Name() != "keycloak" {
		t.Fatalf("expected Name() == %q, got %q", "keycloak", kc.Name())
	}
}

func TestKeycloakDiscover(t *testing.T) {
	// Use a two-step approach: capture the URL via a variable the handler closes over.
	var srvURL string
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/my-realm/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"device_authorization_endpoint": srvURL + "/realms/my-realm/protocol/openid-connect/auth/device",
			"token_endpoint":                srvURL + "/realms/my-realm/protocol/openid-connect/token",
		})
	}))
	defer srv2.Close()
	srvURL = srv2.URL

	issuerURL := srv2.URL + "/realms/my-realm"
	kc := NewKeycloakAuthenticator(issuerURL, "my-client", []string{"openid"}, srv2.Client())

	endpoints, err := kc.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error: %v", err)
	}
	if endpoints.DeviceAuthorizationEndpoint == "" {
		t.Error("expected DeviceAuthorizationEndpoint to be non-empty")
	}
	if endpoints.TokenEndpoint == "" {
		t.Error("expected TokenEndpoint to be non-empty")
	}
	if !strings.Contains(endpoints.DeviceAuthorizationEndpoint, "auth/device") {
		t.Errorf("unexpected DeviceAuthorizationEndpoint: %s", endpoints.DeviceAuthorizationEndpoint)
	}
	if !strings.Contains(endpoints.TokenEndpoint, "token") {
		t.Errorf("unexpected TokenEndpoint: %s", endpoints.TokenEndpoint)
	}
}

func TestKeycloakDiscoverMissingDeviceEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"token_endpoint": "https://keycloak.example.com/realms/my-realm/protocol/openid-connect/token",
		})
	}))
	defer srv.Close()

	issuerURL := srv.URL + "/realms/my-realm"
	kc := NewKeycloakAuthenticator(issuerURL, "my-client", []string{"openid"}, srv.Client())

	_, err := kc.Discover(context.Background())
	if err == nil {
		t.Fatal("expected error when device_authorization_endpoint is missing, got nil")
	}
	if !strings.Contains(err.Error(), "OAuth 2.0 Device Authorization Grant") {
		t.Errorf("error should mention enabling the grant in Keycloak, got: %v", err)
	}
}

func TestKeycloakStartDeviceAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               "dev-code-keycloak",
			"user_code":                 "AAAA-BBBB",
			"verification_uri":          "https://keycloak.example.com/realms/my-realm/device",
			"verification_uri_complete": "https://keycloak.example.com/realms/my-realm/device?user_code=AAAA-BBBB",
			"expires_in":                600,
			"interval":                  5,
		})
	}))
	defer srv.Close()

	endpoints := &OIDCEndpoints{
		DeviceAuthorizationEndpoint: srv.URL + "/device",
		TokenEndpoint:               srv.URL + "/token",
	}
	kc := NewKeycloakAuthenticator("https://keycloak.example.com/realms/my-realm", "my-client", []string{"openid"}, srv.Client())

	resp, err := kc.StartDeviceAuth(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("StartDeviceAuth() error: %v", err)
	}
	if resp.DeviceCode != "dev-code-keycloak" {
		t.Errorf("expected DeviceCode %q, got %q", "dev-code-keycloak", resp.DeviceCode)
	}
	if resp.UserCode != "AAAA-BBBB" {
		t.Errorf("expected UserCode %q, got %q", "AAAA-BBBB", resp.UserCode)
	}
	if resp.ExpiresIn != 600 {
		t.Errorf("expected ExpiresIn 600, got %d", resp.ExpiresIn)
	}
	if resp.Interval != 5 {
		t.Errorf("expected Interval 5, got %d", resp.Interval)
	}
	if resp.VerificationURI == "" {
		t.Error("expected VerificationURI to be non-empty")
	}
}

func TestKeycloakPollForToken(t *testing.T) {
	var callCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		n := atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			// First call: authorization_pending
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "authorization_pending",
			})
			return
		}
		// Second call: success
		json.NewEncoder(w).Encode(map[string]string{
			"id_token":     "kc-id-token",
			"access_token": "kc-access-token",
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	endpoints := &OIDCEndpoints{
		DeviceAuthorizationEndpoint: srv.URL + "/device",
		TokenEndpoint:               srv.URL + "/token",
	}
	kc := NewKeycloakAuthenticator("https://keycloak.example.com/realms/my-realm", "my-client", []string{"openid"}, srv.Client())

	tok, err := kc.PollForToken(context.Background(), endpoints, "dev-code-keycloak", 1)
	if err != nil {
		t.Fatalf("PollForToken() error: %v", err)
	}
	if tok.IDToken != "kc-id-token" {
		t.Errorf("expected IDToken %q, got %q", "kc-id-token", tok.IDToken)
	}
	if tok.AccessToken != "kc-access-token" {
		t.Errorf("expected AccessToken %q, got %q", "kc-access-token", tok.AccessToken)
	}
	if atomic.LoadInt32(&callCount) < 2 {
		t.Errorf("expected at least 2 token endpoint calls (pending then success), got %d", callCount)
	}
}
