package steps

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// stsHints maps well-known STS error codes to actionable diagnostic messages.
var stsHints = map[string]string{
	"AccessDenied":            "Check that the role's trust policy includes your OIDC provider and the aud/sub claims match",
	"InvalidIdentityToken":    "Token may be expired or the FlashBlade cannot reach the IDP's JWKS endpoint to validate signatures",
	"MalformedPolicyDocument": "The role's trust policy syntax is invalid — check conditions and principal format",
	"ExpiredTokenException":   "The OIDC token has expired. Re-authenticate and try again",
}

// stsCredentials holds the parsed credential fields from a successful
// AssumeRoleWithWebIdentity response.
type stsCredentials struct {
	AccessKeyId     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

// stsAssumedRoleUser holds the assumed-role ARN from the response.
type stsAssumedRoleUser struct {
	Arn string `xml:"Arn"`
}

// stsAssumeRoleWithWebIdentityResponse is the top-level XML envelope returned
// by a successful call.
type stsAssumeRoleWithWebIdentityResponse struct {
	XMLName xml.Name `xml:"AssumeRoleWithWebIdentityResponse"`
	Result  struct {
		Credentials    stsCredentials     `xml:"Credentials"`
		AssumedRoleUser stsAssumedRoleUser `xml:"AssumedRoleUser"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
}

// stsErrorResponse is the XML envelope returned on error.
type stsErrorResponse struct {
	XMLName xml.Name `xml:"ErrorResponse"`
	Error   struct {
		Type    string `xml:"Type"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// STSAssumeStep exchanges an OIDC token for temporary S3 credentials via the
// FlashBlade STS VIP using the AWS STS Query API (AssumeRoleWithWebIdentity).
type STSAssumeStep struct{}

// NewSTSAssumeStep returns a new STSAssumeStep.
func NewSTSAssumeStep() *STSAssumeStep {
	return &STSAssumeStep{}
}

// Name returns the step name used by the runner and renderer.
func (s *STSAssumeStep) Name() string {
	return "STSAssume"
}

// Execute performs AssumeRoleWithWebIdentity against the STS endpoint in
// ctx.Config.STSEndpoint. On success it populates ctx with the returned
// temporary credentials and returns a StepResult with all credential fields
// (SecretAccessKey is marked Sensitive).
func (s *STSAssumeStep) Execute(ctx *FlowContext) (*StepResult, error) {
	if ctx.IDToken == "" {
		return nil, &StepError{
			Err:  fmt.Errorf("no ID token present; DeviceAuth must run before STSAssume"),
			Hint: "Ensure the DeviceAuth step succeeds and sets ctx.IDToken.",
		}
	}

	sessionName := fmt.Sprintf("fbsts-validate-%d", time.Now().Unix())
	duration := ctx.Config.Duration
	if duration <= 0 {
		duration = 3600
	}

	params := url.Values{}
	params.Set("Action", "AssumeRoleWithWebIdentity")
	params.Set("Version", "2011-06-15")
	params.Set("RoleArn", ctx.Config.RoleARN)
	params.Set("RoleSessionName", sessionName)
	params.Set("WebIdentityToken", ctx.IDToken)
	params.Set("DurationSeconds", fmt.Sprintf("%d", duration))

	endpoint := ctx.Config.STSEndpoint
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("failed to build STS request: %w", err),
			Hint: "Check that STSEndpoint is a valid URL.",
		}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := ctx.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("STS request failed: %w", err),
			Hint: "Verify the FlashBlade STS VIP is reachable and the TLS certificate is trusted.",
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("failed to read STS response body: %w", err),
			Hint: "Network error reading STS response.",
		}
	}

	if resp.StatusCode != http.StatusOK {
		var errResp stsErrorResponse
		code := ""
		message := ""
		if xmlErr := xml.Unmarshal(body, &errResp); xmlErr == nil {
			code = errResp.Error.Code
			message = errResp.Error.Message
		}
		hint := stsHints[code]
		errMsg := fmt.Sprintf("STS returned HTTP %d", resp.StatusCode)
		if code != "" {
			errMsg = fmt.Sprintf("STS error %s: %s", code, message)
		}
		return nil, &StepError{
			Err:         fmt.Errorf("%s", errMsg),
			Hint:        hint,
			Code:        code,
			HTTPStatus:  resp.StatusCode,
			RawResponse: string(body),
		}
	}

	var assumeResp stsAssumeRoleWithWebIdentityResponse
	if err := xml.Unmarshal(body, &assumeResp); err != nil {
		return nil, &StepError{
			Err:         fmt.Errorf("failed to parse STS success response: %w", err),
			Hint:        "The STS response was not valid XML. Check the FlashBlade firmware version.",
			RawResponse: string(body),
		}
	}

	creds := assumeResp.Result.Credentials
	ctx.AccessKeyId = creds.AccessKeyId
	ctx.SecretAccessKey = creds.SecretAccessKey
	ctx.SessionToken = creds.SessionToken
	ctx.AssumedRoleARN = assumeResp.Result.AssumedRoleUser.Arn

	if creds.Expiration != "" {
		if t, err := time.Parse(time.RFC3339, creds.Expiration); err == nil {
			ctx.Expiration = t
		}
	}

	fields := []Field{
		{Label: "RoleARN", Value: ctx.Config.RoleARN},
		{Label: "AssumedRoleARN", Value: ctx.AssumedRoleARN},
		{Label: "AccessKeyId", Value: ctx.AccessKeyId},
		{Label: "SecretAccessKey", Value: ctx.SecretAccessKey, Sensitive: !ctx.Config.Unmask},
		{Label: "SessionToken", Value: ctx.SessionToken, Sensitive: !ctx.Config.Unmask},
		{Label: "Expiration", Value: creds.Expiration},
	}

	return &StepResult{
		Title:  "STS Credentials Obtained",
		Fields: fields,
	}, nil
}
