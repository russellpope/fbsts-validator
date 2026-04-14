package steps

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OktaDeviceAuthStep performs the OAuth 2.0 device authorization grant flow
// against Okta to obtain an OIDC ID token and access token.
type OktaDeviceAuthStep struct{}

// NewOktaDeviceAuthStep returns a new OktaDeviceAuthStep.
func NewOktaDeviceAuthStep() *OktaDeviceAuthStep {
	return &OktaDeviceAuthStep{}
}

// Name returns the step name used by the runner and renderer.
func (s *OktaDeviceAuthStep) Name() string {
	return "OktaDeviceAuth"
}

// oidcDiscovery holds the relevant fields from the OIDC discovery document.
type oidcDiscovery struct {
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
}

// deviceAuthResponse holds the response from the device authorization endpoint.
type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// tokenResponse holds the response from the token endpoint.
type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
}

// Execute runs the device authorization grant flow. If Config.PreSuppliedToken
// is set, it skips the flow and sets ctx.IDToken directly.
func (s *OktaDeviceAuthStep) Execute(ctx *FlowContext) (*StepResult, error) {
	// Short-circuit: if the caller supplied a token, use it directly.
	if ctx.Config.PreSuppliedToken != "" {
		ctx.IDToken = ctx.Config.PreSuppliedToken
		return &StepResult{
			Title: "Okta Device Auth",
			Fields: []Field{
				{Label: "mode", Value: "pre-supplied token"},
			},
		}, nil
	}

	// 1. Fetch OIDC discovery document.
	discovery, err := s.fetchDiscovery(ctx)
	if err != nil {
		return nil, err
	}

	// 2. POST to device authorization endpoint.
	devAuth, err := s.authorizeDevice(ctx, discovery.DeviceAuthorizationEndpoint)
	if err != nil {
		return nil, err
	}

	// 3. Display the user code and verification URL.
	fmt.Printf("\nOpen the following URL in your browser to authenticate:\n\n")
	if devAuth.VerificationURIComplete != "" {
		fmt.Printf("  %s\n\n", devAuth.VerificationURIComplete)
	} else {
		fmt.Printf("  %s\n\n", devAuth.VerificationURI)
	}
	fmt.Printf("User code: %s\n\n", devAuth.UserCode)

	// 4. Poll the token endpoint until authorized or timeout.
	tok, err := s.pollToken(ctx, discovery.TokenEndpoint, devAuth)
	if err != nil {
		return nil, err
	}

	// 5. Populate context.
	ctx.IDToken = tok.IDToken
	ctx.AccessToken = tok.AccessToken

	return &StepResult{
		Title: "Okta Device Auth",
		Fields: []Field{
			{Label: "verification_uri", Value: devAuth.VerificationURI},
			{Label: "user_code", Value: devAuth.UserCode},
			{Label: "token_type", Value: tok.TokenType},
			{Label: "access_token", Value: tok.AccessToken, Sensitive: true},
			{Label: "id_token", Value: tok.IDToken, Sensitive: true},
		},
	}, nil
}

// fetchDiscovery retrieves and parses the OIDC discovery document.
func (s *OktaDeviceAuthStep) fetchDiscovery(ctx *FlowContext) (*oidcDiscovery, error) {
	discoveryURL := strings.TrimRight(ctx.Config.OktaTenantURL, "/") + "/.well-known/openid-configuration"

	resp, err := ctx.HTTPClient.Get(discoveryURL)
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("fetch OIDC discovery: %w", err),
			Hint: "Check that OktaTenantURL is reachable and correct.",
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("read OIDC discovery response: %w", err),
			Hint: "Network error reading the discovery document.",
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &StepError{
			Err:         fmt.Errorf("OIDC discovery returned HTTP %d", resp.StatusCode),
			Hint:        "Verify the Okta tenant URL is correct and the tenant is reachable.",
			HTTPStatus:  resp.StatusCode,
			RawResponse: string(body),
		}
	}

	var doc oidcDiscovery
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, &StepError{
			Err:         fmt.Errorf("parse OIDC discovery JSON: %w", err),
			Hint:        "The discovery endpoint returned unexpected content.",
			RawResponse: string(body),
		}
	}

	if doc.DeviceAuthorizationEndpoint == "" {
		return nil, &StepError{
			Err:         fmt.Errorf("OIDC discovery missing device_authorization_endpoint"),
			Hint:        "The Okta tenant may not support the device authorization grant.",
			RawResponse: string(body),
		}
	}
	if doc.TokenEndpoint == "" {
		return nil, &StepError{
			Err:         fmt.Errorf("OIDC discovery missing token_endpoint"),
			Hint:        "The OIDC discovery document is incomplete.",
			RawResponse: string(body),
		}
	}

	return &doc, nil
}

// authorizeDevice POSTs to the device authorization endpoint and returns the
// device code and user-facing verification details.
func (s *OktaDeviceAuthStep) authorizeDevice(ctx *FlowContext, endpoint string) (*deviceAuthResponse, error) {
	form := url.Values{}
	form.Set("client_id", ctx.Config.OktaClientID)
	form.Set("scope", strings.Join(ctx.Config.OktaScopes, " "))

	resp, err := ctx.HTTPClient.PostForm(endpoint, form)
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("device authorization request: %w", err),
			Hint: "Could not reach the device authorization endpoint.",
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("read device authorization response: %w", err),
			Hint: "Network error reading the device authorization response.",
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &StepError{
			Err:         fmt.Errorf("device authorization returned HTTP %d", resp.StatusCode),
			Hint:        "Check that the client_id and scopes are valid for this Okta tenant.",
			HTTPStatus:  resp.StatusCode,
			RawResponse: string(body),
		}
	}

	var dar deviceAuthResponse
	if err := json.Unmarshal(body, &dar); err != nil {
		return nil, &StepError{
			Err:         fmt.Errorf("parse device authorization JSON: %w", err),
			Hint:        "The device authorization endpoint returned unexpected content.",
			RawResponse: string(body),
		}
	}

	return &dar, nil
}

// pollToken polls the token endpoint until the device is authorized, the
// device code expires, or a non-recoverable error is returned.
func (s *OktaDeviceAuthStep) pollToken(ctx *FlowContext, endpoint string, dar *deviceAuthResponse) (*tokenResponse, error) {
	interval := dar.Interval
	if interval <= 0 {
		interval = 5
	}

	expiresIn := dar.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 300
	}

	deadline := time.Now().Add(time.Duration(expiresIn) * time.Second)

	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(interval) * time.Second)

		tok, done, err := s.tryToken(ctx, endpoint, dar.DeviceCode)
		if err != nil {
			return nil, err
		}
		if done {
			return tok, nil
		}
		if tok != nil && tok.Error == "slow_down" {
			interval++
		}
	}

	return nil, &StepError{
		Err:  fmt.Errorf("device code expired before authorization was completed"),
		Hint: "The user did not complete authorization within the allowed time. Re-run the tool to try again.",
	}
}

// tryToken makes a single attempt to exchange the device code for tokens.
// Returns (tok, true, nil) on success, (tok, false, nil) when still pending,
// and (nil, false, err) on fatal errors.
func (s *OktaDeviceAuthStep) tryToken(ctx *FlowContext, endpoint, deviceCode string) (*tokenResponse, bool, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", deviceCode)
	form.Set("client_id", ctx.Config.OktaClientID)

	resp, err := ctx.HTTPClient.PostForm(endpoint, form)
	if err != nil {
		return nil, false, &StepError{
			Err:  fmt.Errorf("token poll request: %w", err),
			Hint: "Could not reach the token endpoint during polling.",
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, &StepError{
			Err:  fmt.Errorf("read token poll response: %w", err),
			Hint: "Network error reading the token response.",
		}
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, false, &StepError{
			Err:         fmt.Errorf("parse token response JSON: %w", err),
			Hint:        "The token endpoint returned unexpected content.",
			RawResponse: string(body),
		}
	}

	if resp.StatusCode == http.StatusOK && tok.IDToken != "" {
		return &tok, true, nil
	}

	// Recoverable states: keep polling.
	if tok.Error == "authorization_pending" || tok.Error == "slow_down" {
		return &tok, false, nil
	}

	// Any other error is fatal.
	if tok.Error != "" {
		return nil, false, &StepError{
			Err:         fmt.Errorf("token error: %s", tok.Error),
			Hint:        "The device authorization was denied or encountered a fatal error.",
			HTTPStatus:  resp.StatusCode,
			RawResponse: string(body),
		}
	}

	// Non-200 with no parseable error field.
	if resp.StatusCode != http.StatusOK {
		return nil, false, &StepError{
			Err:         fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode),
			Hint:        "Unexpected response from the token endpoint.",
			HTTPStatus:  resp.StatusCode,
			RawResponse: string(body),
		}
	}

	return &tok, false, nil
}
