package idp

import "context"

// OIDCEndpoints holds the endpoints discovered from .well-known/openid-configuration.
type OIDCEndpoints struct {
	DeviceAuthorizationEndpoint string
	TokenEndpoint               string
}

// DeviceAuthResponse holds the response from the device authorization endpoint.
type DeviceAuthResponse struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               int
	Interval                int
}

// TokenResponse holds the tokens returned after successful device authorization.
type TokenResponse struct {
	IDToken     string
	AccessToken string
	TokenType   string
}

// IDPAuthenticator abstracts OIDC device code authentication across providers.
type IDPAuthenticator interface {
	// Name returns the provider name (e.g., "okta", "keycloak").
	Name() string

	// Discover fetches .well-known/openid-configuration and extracts
	// the device_authorization_endpoint and token_endpoint.
	Discover(ctx context.Context) (*OIDCEndpoints, error)

	// StartDeviceAuth initiates the device code flow and returns the
	// verification URI, user code, device code, and poll interval.
	StartDeviceAuth(ctx context.Context, endpoints *OIDCEndpoints) (*DeviceAuthResponse, error)

	// PollForToken polls the token endpoint until the user completes
	// authorization or the device code expires.
	PollForToken(ctx context.Context, endpoints *OIDCEndpoints, deviceCode string, interval int) (*TokenResponse, error)
}
