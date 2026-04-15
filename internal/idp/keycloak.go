package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// KeycloakAuthenticator implements IDPAuthenticator for Keycloak using the
// OIDC device code flow. The issuerURL must already include the realm path,
// e.g. https://keycloak.example.com/realms/my-realm.
type KeycloakAuthenticator struct {
	issuerURL  string
	clientID   string
	scopes     []string
	httpClient *http.Client
}

// NewKeycloakAuthenticator constructs a KeycloakAuthenticator.
func NewKeycloakAuthenticator(issuerURL, clientID string, scopes []string, httpClient *http.Client) *KeycloakAuthenticator {
	return &KeycloakAuthenticator{
		issuerURL:  issuerURL,
		clientID:   clientID,
		scopes:     scopes,
		httpClient: httpClient,
	}
}

// Name returns the provider identifier.
func (k *KeycloakAuthenticator) Name() string {
	return "keycloak"
}

// Discover fetches the OIDC discovery document from
// {issuerURL}/.well-known/openid-configuration and extracts the endpoints
// required for the device code flow.
func (k *KeycloakAuthenticator) Discover(ctx context.Context) (*OIDCEndpoints, error) {
	discoveryURL := strings.TrimRight(k.issuerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("keycloak discover: build request: %w", err)
	}

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak discover: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak discover: unexpected status %d", resp.StatusCode)
	}

	var doc struct {
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
		TokenEndpoint               string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("keycloak discover: decode response: %w", err)
	}

	if doc.DeviceAuthorizationEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery missing device_authorization_endpoint — ensure the Keycloak client has 'OAuth 2.0 Device Authorization Grant' enabled")
	}
	if doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("keycloak discover: OIDC discovery missing token_endpoint")
	}

	return &OIDCEndpoints{
		DeviceAuthorizationEndpoint: doc.DeviceAuthorizationEndpoint,
		TokenEndpoint:               doc.TokenEndpoint,
	}, nil
}

// StartDeviceAuth initiates the device authorization flow against Keycloak.
func (k *KeycloakAuthenticator) StartDeviceAuth(ctx context.Context, endpoints *OIDCEndpoints) (*DeviceAuthResponse, error) {
	form := url.Values{}
	form.Set("client_id", k.clientID)
	form.Set("scope", strings.Join(k.scopes, " "))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoints.DeviceAuthorizationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("keycloak start device auth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak start device auth: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak start device auth: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("keycloak start device auth: decode response: %w", err)
	}

	return &DeviceAuthResponse{
		DeviceCode:              body.DeviceCode,
		UserCode:                body.UserCode,
		VerificationURI:         body.VerificationURI,
		VerificationURIComplete: body.VerificationURIComplete,
		ExpiresIn:               body.ExpiresIn,
		Interval:                body.Interval,
	}, nil
}

// PollForToken polls the token endpoint until authorization completes or the
// context is cancelled.
func (k *KeycloakAuthenticator) PollForToken(ctx context.Context, endpoints *OIDCEndpoints, deviceCode string, interval int) (*TokenResponse, error) {
	wait := time.Duration(interval) * time.Second
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}

		tok, pending, err := k.tryToken(ctx, endpoints.TokenEndpoint, deviceCode)
		if err != nil {
			return nil, err
		}
		if pending {
			continue
		}
		return tok, nil
	}
}

// tryToken makes a single token request. It returns (token, false, nil) on
// success, (nil, true, nil) when the device authorization is still pending,
// or (nil, false, err) on a terminal error.
func (k *KeycloakAuthenticator) tryToken(ctx context.Context, tokenEndpoint, deviceCode string) (*TokenResponse, bool, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", deviceCode)
	form.Set("client_id", k.clientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, false, fmt.Errorf("keycloak poll token: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("keycloak poll token: %w", err)
	}
	defer resp.Body.Close()

	var body map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, false, fmt.Errorf("keycloak poll token: decode response: %w", err)
	}

	if errVal, ok := body["error"]; ok {
		var errStr string
		_ = json.Unmarshal(errVal, &errStr)
		switch errStr {
		case "authorization_pending", "slow_down":
			return nil, true, nil
		default:
			desc := ""
			if descVal, ok := body["error_description"]; ok {
				_ = json.Unmarshal(descVal, &desc)
			}
			if desc != "" {
				return nil, false, fmt.Errorf("keycloak poll token: %s — %s", errStr, desc)
			}
			return nil, false, fmt.Errorf("keycloak poll token: %s", errStr)
		}
	}

	var idToken, accessToken, tokenType string
	if v, ok := body["id_token"]; ok {
		_ = json.Unmarshal(v, &idToken)
	}
	if v, ok := body["access_token"]; ok {
		_ = json.Unmarshal(v, &accessToken)
	}
	if v, ok := body["token_type"]; ok {
		_ = json.Unmarshal(v, &tokenType)
	}

	return &TokenResponse{
		IDToken:     idToken,
		AccessToken: accessToken,
		TokenType:   tokenType,
	}, false, nil
}
