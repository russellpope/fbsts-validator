package steps

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestOktaDeviceAuthStepName(t *testing.T) {
	step := NewOktaDeviceAuthStep()
	if step.Name() != "OktaDeviceAuth" {
		t.Errorf("Name() = %q, want OktaDeviceAuth", step.Name())
	}
}

func TestOktaDeviceAuthSuccess(t *testing.T) {
	// Build a fake JWT to return from the token endpoint.
	fakeJWT := buildTestJWT(
		map[string]interface{}{"alg": "RS256", "kid": "key1", "typ": "JWT"},
		map[string]interface{}{
			"iss": "https://example.okta.com",
			"sub": "testuser@example.com",
			"aud": "test-client-id",
			"exp": 9999999999.0,
		},
	)

	// tokenCalls counts how many times /v1/token has been hit.
	var tokenCalls int32

	mux := http.NewServeMux()

	// Handler registered after server starts — we need the server URL in the
	// discovery document, so we set up the mux handlers once we have it.
	var serverURL string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	}))
	defer ts.Close()

	serverURL = ts.URL

	// /.well-known/openid-configuration
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"device_authorization_endpoint": serverURL + "/v1/device/authorize",
			"token_endpoint":                serverURL + "/v1/token",
		})
	})

	// /v1/device/authorize
	mux.HandleFunc("/v1/device/authorize", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               "dev-code-abc",
			"user_code":                 "ABCD-1234",
			"verification_uri":          "https://example.okta.com/activate",
			"verification_uri_complete": "https://example.okta.com/activate?user_code=ABCD-1234",
			"expires_in":                300,
			"interval":                  1,
		})
	})

	// /v1/token — first call returns authorization_pending, second returns tokens.
	mux.HandleFunc("/v1/token", func(w http.ResponseWriter, r *http.Request) {
		call := atomic.AddInt32(&tokenCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		if call == 1 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "authorization_pending",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id_token":     fakeJWT,
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	cfg := &Config{
		OktaTenantURL: serverURL,
		OktaClientID:  "test-client-id",
		OktaScopes:    []string{"openid", "profile"},
	}
	ctx := NewFlowContext(cfg, ts.Client())

	step := NewOktaDeviceAuthStep()
	result, err := step.Execute(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if ctx.IDToken != fakeJWT {
		t.Errorf("ctx.IDToken = %q, want fake JWT", ctx.IDToken)
	}
	if ctx.AccessToken != "fake-access-token" {
		t.Errorf("ctx.AccessToken = %q, want fake-access-token", ctx.AccessToken)
	}
}

func TestOktaDeviceAuthBadDiscovery(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	cfg := &Config{
		OktaTenantURL: ts.URL,
		OktaClientID:  "test-client-id",
		OktaScopes:    []string{"openid"},
	}
	ctx := NewFlowContext(cfg, ts.Client())

	step := NewOktaDeviceAuthStep()
	_, err := step.Execute(ctx)

	if err == nil {
		t.Fatal("expected error for bad discovery endpoint, got nil")
	}

	var se *StepError
	if !isStepError(err, &se) {
		t.Fatalf("expected *StepError, got %T: %v", err, err)
	}
	if se.HTTPStatus != http.StatusInternalServerError {
		t.Errorf("HTTPStatus = %d, want %d", se.HTTPStatus, http.StatusInternalServerError)
	}
}

func TestOktaDeviceAuthPreSuppliedToken(t *testing.T) {
	// The test server should never be called when a pre-supplied token is set.
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer ts.Close()

	const preSupplied = "pre.supplied.token"

	cfg := &Config{
		OktaTenantURL:    ts.URL,
		OktaClientID:     "test-client-id",
		OktaScopes:       []string{"openid"},
		PreSuppliedToken: preSupplied,
	}
	ctx := NewFlowContext(cfg, ts.Client())

	step := NewOktaDeviceAuthStep()
	result, err := step.Execute(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if ctx.IDToken != preSupplied {
		t.Errorf("ctx.IDToken = %q, want %q", ctx.IDToken, preSupplied)
	}
	if called {
		t.Error("HTTP server was called but should have been skipped for pre-supplied token")
	}
}

// isStepError is a helper to type-assert err to *StepError and populate dst.
func isStepError(err error, dst **StepError) bool {
	if se, ok := err.(*StepError); ok {
		*dst = se
		return true
	}
	return false
}
