package steps

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
)

func buildTestJWT(header, payload map[string]interface{}) string {
	hJSON, _ := json.Marshal(header)
	pJSON, _ := json.Marshal(payload)
	h := base64.RawURLEncoding.EncodeToString(hJSON)
	p := base64.RawURLEncoding.EncodeToString(pJSON)
	return h + "." + p + ".fakesignature"
}

func TestTokenDecodeExecute(t *testing.T) {
	header := map[string]interface{}{"alg": "RS256", "kid": "test-key-id", "typ": "JWT"}
	payload := map[string]interface{}{
		"iss":    "https://test.okta.com",
		"sub":    "user@example.com",
		"aud":    "test-client-id",
		"exp":    1700000000.0,
		"iat":    1699999000.0,
		"groups": []interface{}{"admin", "users"},
	}

	jwt := buildTestJWT(header, payload)

	ctx := NewFlowContext(&Config{}, &http.Client{})
	ctx.IDToken = jwt

	step := NewTokenDecodeStep()
	result, err := step.Execute(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if ctx.TokenHeader["alg"] != "RS256" {
		t.Errorf("TokenHeader alg = %v, want RS256", ctx.TokenHeader["alg"])
	}
	if ctx.TokenClaims["sub"] != "user@example.com" {
		t.Errorf("TokenClaims sub = %v, want user@example.com", ctx.TokenClaims["sub"])
	}
	if ctx.TokenClaims["iss"] != "https://test.okta.com" {
		t.Errorf("TokenClaims iss = %v", ctx.TokenClaims["iss"])
	}
}

func TestTokenDecodeStepName(t *testing.T) {
	step := NewTokenDecodeStep()
	if step.Name() != "TokenDecode" {
		t.Errorf("Name() = %q, want TokenDecode", step.Name())
	}
}

func TestTokenDecodeInvalidJWT(t *testing.T) {
	ctx := NewFlowContext(&Config{}, &http.Client{})
	ctx.IDToken = "not-a-jwt"

	step := NewTokenDecodeStep()
	_, err := step.Execute(ctx)

	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestTokenDecodeEmptyToken(t *testing.T) {
	ctx := NewFlowContext(&Config{}, &http.Client{})
	ctx.IDToken = ""

	step := NewTokenDecodeStep()
	_, err := step.Execute(ctx)

	if err == nil {
		t.Error("expected error for empty token")
	}
}

func TestTokenDecodeBadBase64(t *testing.T) {
	ctx := NewFlowContext(&Config{}, &http.Client{})
	ctx.IDToken = "!!!invalid-base64!!!.!!!also-bad!!!.sig"

	step := NewTokenDecodeStep()
	_, err := step.Execute(ctx)

	if err == nil {
		t.Error("expected error for bad base64")
	}
}
