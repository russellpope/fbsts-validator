package idp

import (
	"context"
	"net/http"
)

// KeycloakAuthenticator implements IDPAuthenticator for Keycloak.
// TODO: full implementation in Task 3.
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
func (a *KeycloakAuthenticator) Name() string {
	return "keycloak"
}

// Discover fetches .well-known/openid-configuration and returns the parsed endpoints.
func (a *KeycloakAuthenticator) Discover(ctx context.Context) (*OIDCEndpoints, error) {
	panic("KeycloakAuthenticator.Discover: not yet implemented")
}

// StartDeviceAuth initiates the device authorization grant flow.
func (a *KeycloakAuthenticator) StartDeviceAuth(ctx context.Context, endpoints *OIDCEndpoints) (*DeviceAuthResponse, error) {
	panic("KeycloakAuthenticator.StartDeviceAuth: not yet implemented")
}

// PollForToken polls the token endpoint until authorization completes.
func (a *KeycloakAuthenticator) PollForToken(ctx context.Context, endpoints *OIDCEndpoints, deviceCode string, interval int) (*TokenResponse, error) {
	panic("KeycloakAuthenticator.PollForToken: not yet implemented")
}
