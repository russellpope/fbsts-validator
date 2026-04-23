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

func TestEntraIDAuthenticatorName(t *testing.T) {
	e := NewEntraIDAuthenticator("https://login.microsoftonline.com/tenant/v2.0", "client", []string{"openid"}, http.DefaultClient)
	if e.Name() != "entraid" {
		t.Fatalf("expected Name() == %q, got %q", "entraid", e.Name())
	}
}

func TestEntraIDDiscover(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tenant/v2.0/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"device_authorization_endpoint": srvURL + "/tenant/oauth2/v2.0/devicecode",
			"token_endpoint":                srvURL + "/tenant/oauth2/v2.0/token",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	issuerURL := srv.URL + "/tenant/v2.0"
	e := NewEntraIDAuthenticator(issuerURL, "client", []string{"openid"}, srv.Client())

	endpoints, err := e.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error: %v", err)
	}
	if !strings.Contains(endpoints.DeviceAuthorizationEndpoint, "devicecode") {
		t.Errorf("unexpected DeviceAuthorizationEndpoint: %s", endpoints.DeviceAuthorizationEndpoint)
	}
	if !strings.Contains(endpoints.TokenEndpoint, "token") {
		t.Errorf("unexpected TokenEndpoint: %s", endpoints.TokenEndpoint)
	}
}

func TestEntraIDDiscoverMissingDeviceEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"token_endpoint": "https://example.test/token",
		})
	}))
	defer srv.Close()

	e := NewEntraIDAuthenticator(srv.URL+"/tenant/v2.0", "client", []string{"openid"}, srv.Client())
	_, err := e.Discover(context.Background())
	if err == nil {
		t.Fatal("expected error when device_authorization_endpoint is missing, got nil")
	}
	if !strings.Contains(err.Error(), "public client flows") {
		t.Errorf("error should mention enabling public client flows on the Entra app registration, got: %v", err)
	}
}

func TestEntraIDDiscoverNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	e := NewEntraIDAuthenticator(srv.URL+"/tenant/v2.0", "client", []string{"openid"}, srv.Client())
	_, err := e.Discover(context.Background())
	if err == nil {
		t.Fatal("expected error for non-200 status, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should include the status code, got: %v", err)
	}
}

func TestEntraIDStartDeviceAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			t.Errorf("expected form content-type, got %q", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if got := r.Form.Get("client_id"); got != "app-client" {
			t.Errorf("expected client_id=app-client, got %q", got)
		}
		if got := r.Form.Get("scope"); got != "openid profile api://app/.default" {
			t.Errorf("unexpected scope form value: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               "dev-code-entra",
			"user_code":                 "ABCD-EFGH",
			"verification_uri":          "https://microsoft.com/devicelogin",
			"verification_uri_complete": "https://microsoft.com/devicelogin?user_code=ABCD-EFGH",
			"expires_in":                900,
			"interval":                  5,
			"message":                   "To sign in, use a web browser to open...",
		})
	}))
	defer srv.Close()

	endpoints := &OIDCEndpoints{
		DeviceAuthorizationEndpoint: srv.URL + "/devicecode",
		TokenEndpoint:               srv.URL + "/token",
	}
	e := NewEntraIDAuthenticator("https://login.microsoftonline.com/t/v2.0", "app-client", []string{"openid", "profile", "api://app/.default"}, srv.Client())

	resp, err := e.StartDeviceAuth(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("StartDeviceAuth() error: %v", err)
	}
	if resp.DeviceCode != "dev-code-entra" {
		t.Errorf("expected DeviceCode dev-code-entra, got %q", resp.DeviceCode)
	}
	if resp.UserCode != "ABCD-EFGH" {
		t.Errorf("expected UserCode ABCD-EFGH, got %q", resp.UserCode)
	}
	if resp.ExpiresIn != 900 {
		t.Errorf("expected ExpiresIn 900, got %d", resp.ExpiresIn)
	}
	if resp.Interval != 5 {
		t.Errorf("expected Interval 5, got %d", resp.Interval)
	}
}

func TestEntraIDPollForTokenPendingThenSuccess(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:device_code" {
			t.Errorf("unexpected grant_type: %q", got)
		}
		if got := r.Form.Get("device_code"); got != "dev-code-entra" {
			t.Errorf("expected device_code=dev-code-entra, got %q", got)
		}
		n := atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"id_token":     "entra-id-token",
			"access_token": "entra-access-token",
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	endpoints := &OIDCEndpoints{
		DeviceAuthorizationEndpoint: srv.URL + "/devicecode",
		TokenEndpoint:               srv.URL + "/token",
	}
	e := NewEntraIDAuthenticator("https://login.microsoftonline.com/t/v2.0", "app-client", []string{"openid"}, srv.Client())

	tok, err := e.PollForToken(context.Background(), endpoints, "dev-code-entra", 1)
	if err != nil {
		t.Fatalf("PollForToken() error: %v", err)
	}
	if tok.IDToken != "entra-id-token" {
		t.Errorf("expected IDToken entra-id-token, got %q", tok.IDToken)
	}
	if tok.AccessToken != "entra-access-token" {
		t.Errorf("expected AccessToken entra-access-token, got %q", tok.AccessToken)
	}
	if atomic.LoadInt32(&callCount) < 2 {
		t.Errorf("expected at least 2 token endpoint calls, got %d", callCount)
	}
}

func TestEntraIDPollForTokenSlowDown(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "slow_down"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": "t", "access_token": "a", "token_type": "Bearer"})
	}))
	defer srv.Close()

	endpoints := &OIDCEndpoints{TokenEndpoint: srv.URL + "/token"}
	e := NewEntraIDAuthenticator("https://login.microsoftonline.com/t/v2.0", "c", []string{"openid"}, srv.Client())

	tok, err := e.PollForToken(context.Background(), endpoints, "d", 1)
	if err != nil {
		t.Fatalf("PollForToken: %v", err)
	}
	if tok.IDToken != "t" {
		t.Errorf("expected IDToken t, got %q", tok.IDToken)
	}
}

func TestEntraIDPollForTokenTerminalError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "expired_token",
			"error_description": "The code has expired",
		})
	}))
	defer srv.Close()

	endpoints := &OIDCEndpoints{TokenEndpoint: srv.URL + "/token"}
	e := NewEntraIDAuthenticator("https://login.microsoftonline.com/t/v2.0", "c", []string{"openid"}, srv.Client())

	_, err := e.PollForToken(context.Background(), endpoints, "d", 1)
	if err == nil {
		t.Fatal("expected terminal error, got nil")
	}
	if !strings.Contains(err.Error(), "expired_token") {
		t.Errorf("error should include Entra error code, got: %v", err)
	}
	if !strings.Contains(err.Error(), "The code has expired") {
		t.Errorf("error should include error_description, got: %v", err)
	}
}
