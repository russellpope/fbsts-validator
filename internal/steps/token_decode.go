package steps

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// TokenDecodeStep decodes the OIDC JWT header and claims for inspection.
// It does NOT verify the signature — that is FlashBlade's responsibility.
type TokenDecodeStep struct{}

// NewTokenDecodeStep returns a new TokenDecodeStep.
func NewTokenDecodeStep() *TokenDecodeStep {
	return &TokenDecodeStep{}
}

// Name returns the step name used by the runner and renderer.
func (s *TokenDecodeStep) Name() string {
	return "TokenDecode"
}

// Execute decodes the JWT in ctx.IDToken, populating ctx.TokenHeader and
// ctx.TokenClaims, then returns a StepResult with human-readable fields.
func (s *TokenDecodeStep) Execute(ctx *FlowContext) (*StepResult, error) {
	if ctx.IDToken == "" {
		return nil, &StepError{
			Err:  fmt.Errorf("no ID token present"),
			Hint: "The previous step must set ctx.IDToken before TokenDecode runs.",
		}
	}

	parts := strings.Split(ctx.IDToken, ".")
	if len(parts) != 3 {
		return nil, &StepError{
			Err:  fmt.Errorf("malformed JWT: expected 3 parts, got %d", len(parts)),
			Hint: "A valid JWT has three base64url-encoded parts separated by '.'.",
		}
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("failed to base64-decode JWT header: %w", err),
			Hint: "The JWT header is not valid base64url.",
		}
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("failed to base64-decode JWT payload: %w", err),
			Hint: "The JWT payload is not valid base64url.",
		}
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("failed to JSON-unmarshal JWT header: %w", err),
			Hint: "The JWT header did not decode to a valid JSON object.",
		}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("failed to JSON-unmarshal JWT payload: %w", err),
			Hint: "The JWT payload did not decode to a valid JSON object.",
		}
	}

	ctx.TokenHeader = header
	ctx.TokenClaims = claims

	fields := buildTokenFields(header, claims)

	return &StepResult{
		Title:  "Token Decoded",
		Fields: fields,
	}, nil
}

// buildTokenFields assembles the display fields for the StepResult.
func buildTokenFields(header, claims map[string]interface{}) []Field {
	var fields []Field

	// Header fields: alg, kid, typ
	for _, key := range []string{"alg", "kid", "typ"} {
		if v, ok := header[key]; ok {
			fields = append(fields, Field{
				Label: fmt.Sprintf("header.%s", key),
				Value: fmt.Sprintf("%v", v),
			})
		}
	}

	// Trust-policy-relevant claims (marked with (*))
	trustClaims := map[string]bool{
		"iss":    true,
		"sub":    true,
		"aud":    true,
		"groups": true,
	}

	// Emit claims in a stable order: trust-policy ones first, then remainder.
	orderedFirst := []string{"iss", "sub", "aud", "groups"}
	seen := make(map[string]bool)

	for _, key := range orderedFirst {
		v, ok := claims[key]
		if !ok {
			continue
		}
		seen[key] = true
		fields = append(fields, Field{
			Label: fmt.Sprintf("claim.%s (*)", key),
			Value: formatClaimValue(v),
		})
	}

	// Remaining claims
	for _, key := range []string{"exp", "iat", "nbf", "jti", "nonce", "at_hash", "c_hash"} {
		if trustClaims[key] {
			continue
		}
		v, ok := claims[key]
		if !ok || seen[key] {
			continue
		}
		seen[key] = true

		label := fmt.Sprintf("claim.%s", key)
		value := formatClaimValue(v)

		// For exp, also show time remaining / elapsed.
		if key == "exp" {
			if expFloat, ok := v.(float64); ok {
				expTime := time.Unix(int64(expFloat), 0)
				diff := time.Until(expTime)
				if diff > 0 {
					value = fmt.Sprintf("%s (expires in %s)", value, diff.Round(time.Second))
				} else {
					value = fmt.Sprintf("%s (expired %s ago)", value, (-diff).Round(time.Second))
				}
			}
		}

		fields = append(fields, Field{Label: label, Value: value})
	}

	// Catch-all for any remaining claims not explicitly listed above.
	for key, v := range claims {
		if seen[key] || trustClaims[key] {
			continue
		}
		seen[key] = true
		fields = append(fields, Field{
			Label: fmt.Sprintf("claim.%s", key),
			Value: formatClaimValue(v),
		})
	}

	return fields
}

// formatClaimValue converts a claim value to a display string. Arrays are
// rendered as [item1, item2, ...].
func formatClaimValue(v interface{}) string {
	switch val := v.(type) {
	case []interface{}:
		items := make([]string, 0, len(val))
		for _, item := range val {
			items = append(items, fmt.Sprintf("%v", item))
		}
		return "[" + strings.Join(items, ", ") + "]"
	default:
		return fmt.Sprintf("%v", val)
	}
}
