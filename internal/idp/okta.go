package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OktaAuthenticator implements IDPAuthenticator using Okta's OIDC device code flow.
type OktaAuthenticator struct {
	tenantURL  string
	clientID   string
	scopes     []string
	httpClient *http.Client
}

// NewOktaAuthenticator constructs an OktaAuthenticator.
func NewOktaAuthenticator(tenantURL, clientID string, scopes []string, httpClient *http.Client) *OktaAuthenticator {
	return &OktaAuthenticator{
		tenantURL:  tenantURL,
		clientID:   clientID,
		scopes:     scopes,
		httpClient: httpClient,
	}
}

// Name returns the provider identifier.
func (a *OktaAuthenticator) Name() string {
	return "okta"
}

// oidcDiscoveryDoc holds the relevant fields from the OIDC discovery document.
type oidcDiscoveryDoc struct {
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
}

// Discover fetches .well-known/openid-configuration and returns the parsed endpoints.
func (a *OktaAuthenticator) Discover(ctx context.Context) (*OIDCEndpoints, error) {
	discoveryURL := strings.TrimRight(a.tenantURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build discovery request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch OIDC discovery: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read OIDC discovery response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned HTTP %d", resp.StatusCode)
	}

	var doc oidcDiscoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse OIDC discovery JSON: %w", err)
	}

	if doc.DeviceAuthorizationEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery missing device_authorization_endpoint")
	}
	if doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery missing token_endpoint")
	}

	return &OIDCEndpoints{
		DeviceAuthorizationEndpoint: doc.DeviceAuthorizationEndpoint,
		TokenEndpoint:               doc.TokenEndpoint,
	}, nil
}

// deviceAuthJSON holds the raw JSON from the device authorization endpoint.
type deviceAuthJSON struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// StartDeviceAuth POSTs to the device authorization endpoint and returns the response.
func (a *OktaAuthenticator) StartDeviceAuth(ctx context.Context, endpoints *OIDCEndpoints) (*DeviceAuthResponse, error) {
	form := url.Values{}
	form.Set("client_id", a.clientID)
	form.Set("scope", strings.Join(a.scopes, " "))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoints.DeviceAuthorizationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build device authorization request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device authorization request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read device authorization response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device authorization returned HTTP %d", resp.StatusCode)
	}

	var dar deviceAuthJSON
	if err := json.Unmarshal(body, &dar); err != nil {
		return nil, fmt.Errorf("parse device authorization JSON: %w", err)
	}

	return &DeviceAuthResponse{
		DeviceCode:              dar.DeviceCode,
		UserCode:                dar.UserCode,
		VerificationURI:         dar.VerificationURI,
		VerificationURIComplete: dar.VerificationURIComplete,
		ExpiresIn:               dar.ExpiresIn,
		Interval:                dar.Interval,
	}, nil
}

// tokenJSON holds the raw JSON from the token endpoint.
type tokenJSON struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
}

// PollForToken polls the token endpoint until the user completes authorization
// or the 5-minute deadline is reached.
func (a *OktaAuthenticator) PollForToken(ctx context.Context, endpoints *OIDCEndpoints, deviceCode string, interval int) (*TokenResponse, error) {
	if interval <= 0 {
		interval = 5
	}

	deadline := time.Now().Add(5 * time.Minute)

	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(interval) * time.Second)

		tok, done, err := a.tryToken(ctx, endpoints.TokenEndpoint, deviceCode)
		if err != nil {
			return nil, err
		}
		if done {
			return tok, nil
		}
		// tok non-nil with no done signals slow_down — increment interval.
		if tok != nil {
			interval++
		}
		// tok nil means authorization_pending — keep polling at current interval.
	}

	return nil, fmt.Errorf("device code expired before authorization was completed")
}

// tryToken makes a single token exchange attempt.
// Returns (tok, true, nil) on success, (non-nil tok, false, nil) on slow_down,
// (nil, false, nil) on authorization_pending, (nil, false, err) on fatal error.
func (a *OktaAuthenticator) tryToken(ctx context.Context, tokenEndpoint, deviceCode string) (*TokenResponse, bool, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", deviceCode)
	form.Set("client_id", a.clientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, false, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("token poll request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("read token poll response: %w", err)
	}

	var tok tokenJSON
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, false, fmt.Errorf("parse token response JSON: %w", err)
	}

	// Success: HTTP 200 with an ID token present.
	if resp.StatusCode == http.StatusOK && tok.IDToken != "" {
		return &TokenResponse{
			IDToken:     tok.IDToken,
			AccessToken: tok.AccessToken,
			TokenType:   tok.TokenType,
		}, true, nil
	}

	// Recoverable: keep polling.
	if tok.Error == "authorization_pending" {
		return nil, false, nil
	}
	if tok.Error == "slow_down" {
		return &TokenResponse{}, false, nil
	}

	// Any other named error is fatal.
	if tok.Error != "" {
		return nil, false, fmt.Errorf("token error: %s", tok.Error)
	}

	// Non-200 with no parseable error field.
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
	}

	return nil, false, nil
}
