package steps

import (
	"context"
	"fmt"

	"github.com/pure-experimental/rp-fbstsvalidator/internal/browser"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/idp"
)

type DeviceAuthStep struct {
	auth idp.IDPAuthenticator
}

func NewDeviceAuthStep(auth idp.IDPAuthenticator) *DeviceAuthStep {
	return &DeviceAuthStep{auth: auth}
}

func (s *DeviceAuthStep) Name() string {
	return "DeviceAuth"
}

func (s *DeviceAuthStep) Execute(ctx *FlowContext) (*StepResult, error) {
	if ctx.Config.PreSuppliedToken != "" {
		ctx.IDToken = ctx.Config.PreSuppliedToken
		return &StepResult{
			Title: fmt.Sprintf("%s Device Auth", s.auth.Name()),
			Fields: []Field{
				{Label: "mode", Value: "pre-supplied token"},
			},
		}, nil
	}

	bgCtx := context.Background()

	// 1. Discover OIDC endpoints.
	endpoints, err := s.auth.Discover(bgCtx)
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("OIDC discovery failed: %w", err),
			Hint: fmt.Sprintf("Check that the %s configuration URL is reachable and correct.", s.auth.Name()),
		}
	}

	// 2. Start device authorization.
	devAuth, err := s.auth.StartDeviceAuth(bgCtx, endpoints)
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("device authorization failed: %w", err),
			Hint: "Check that the client_id and scopes are valid.",
		}
	}

	// 3. Show compact auth prompt and open browser.
	browserURL := devAuth.VerificationURI
	if devAuth.VerificationURIComplete != "" {
		browserURL = devAuth.VerificationURIComplete
	}
	fmt.Printf("  Authorize: %s  (code: %s)\n", browserURL, devAuth.UserCode)
	browser.Open(browserURL)

	// 4. Poll for token.
	tok, err := s.auth.PollForToken(bgCtx, endpoints, devAuth.DeviceCode, devAuth.Interval)
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("token polling failed: %w", err),
			Hint: "The user may not have completed authorization in time. Re-run the tool to try again.",
		}
	}

	// 5. Populate context.
	ctx.IDToken = tok.IDToken
	ctx.AccessToken = tok.AccessToken

	return &StepResult{
		Title: fmt.Sprintf("%s Device Auth", s.auth.Name()),
		Fields: []Field{
			{Label: "provider", Value: s.auth.Name()},
			{Label: "verification_uri", Value: devAuth.VerificationURI},
			{Label: "user_code", Value: devAuth.UserCode},
			{Label: "token_type", Value: tok.TokenType},
			{Label: "access_token", Value: tok.AccessToken, Sensitive: true},
			{Label: "id_token", Value: tok.IDToken, Sensitive: true},
		},
	}, nil
}
