package steps

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/pure-experimental/rp-fbstsvalidator/internal/idp"
)

func TestDeviceAuthStepName(t *testing.T) {
	auth := idp.NewOktaAuthenticator("https://example.com", "cid", []string{"openid"}, http.DefaultClient)
	step := NewDeviceAuthStep(auth)
	if step.Name() != "DeviceAuth" {
		t.Errorf("Name() = %q, want DeviceAuth", step.Name())
	}
}

func TestDeviceAuthStepPreSuppliedToken(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer ts.Close()

	auth := idp.NewOktaAuthenticator(ts.URL, "cid", []string{"openid"}, ts.Client())
	step := NewDeviceAuthStep(auth)

	cfg := &Config{PreSuppliedToken: "pre.supplied.jwt"}
	ctx := NewFlowContext(cfg, ts.Client())

	result, err := step.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if ctx.IDToken != "pre.supplied.jwt" {
		t.Errorf("ctx.IDToken = %q, want pre.supplied.jwt", ctx.IDToken)
	}
	if called {
		t.Error("HTTP server should not be called for pre-supplied token")
	}
}

func TestDeviceAuthStepSuccess(t *testing.T) {
	fakeJWT := buildTestJWT(
		map[string]interface{}{"alg": "RS256", "typ": "JWT"},
		map[string]interface{}{"iss": "https://test.com", "sub": "user"},
	)

	var tokenCalls int32
	mux := http.NewServeMux()
	var serverURL string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	}))
	defer ts.Close()
	serverURL = ts.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"device_authorization_endpoint": serverURL + "/device/authorize",
			"token_endpoint":                serverURL + "/token",
		})
	})

	mux.HandleFunc("/device/authorize", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":      "dev-code",
			"user_code":        "TEST-1234",
			"verification_uri": "https://example.com/activate",
			"expires_in":       300,
			"interval":         1,
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		call := atomic.AddInt32(&tokenCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		if call == 1 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id_token":     fakeJWT,
			"access_token": "test-access-token",
			"token_type":   "Bearer",
		})
	})

	auth := idp.NewOktaAuthenticator(ts.URL, "test-client", []string{"openid"}, ts.Client())
	step := NewDeviceAuthStep(auth)

	cfg := &Config{}
	ctx := NewFlowContext(cfg, ts.Client())

	result, err := step.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if ctx.IDToken != fakeJWT {
		t.Error("ctx.IDToken should be set to the fake JWT")
	}
	if ctx.AccessToken != "test-access-token" {
		t.Errorf("ctx.AccessToken = %q", ctx.AccessToken)
	}
}
