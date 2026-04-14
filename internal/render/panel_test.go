package render

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

func TestPanelRendererStepStart(t *testing.T) {
	var buf bytes.Buffer
	r := NewPanelRenderer(&buf)
	r.RenderStepStart("OktaDeviceAuth")

	output := buf.String()
	if !strings.Contains(output, "OktaDeviceAuth") {
		t.Errorf("RenderStepStart should contain step name, got: %s", output)
	}
}

func TestPanelRendererStepResult(t *testing.T) {
	var buf bytes.Buffer
	r := NewPanelRenderer(&buf)

	result := &steps.StepResult{
		Title: "Token Decode",
		Fields: []steps.Field{
			{Label: "Algorithm", Value: "RS256", Sensitive: false},
			{Label: "SecretKey", Value: "supersecret", Sensitive: true},
		},
		Duration: 42 * time.Millisecond,
	}
	r.RenderStepResult("TokenDecode", result)

	output := buf.String()
	if !strings.Contains(output, "RS256") {
		t.Error("should display non-sensitive value RS256")
	}
	if strings.Contains(output, "supersecret") {
		t.Error("should NOT display sensitive value in clear text")
	}
	if !strings.Contains(output, "**********") {
		t.Error("should mask sensitive value")
	}
}

func TestPanelRendererStepResultWithSubSteps(t *testing.T) {
	var buf bytes.Buffer
	r := NewPanelRenderer(&buf)

	result := &steps.StepResult{
		Title: "S3 Validate",
		SubSteps: []steps.SubStep{
			{Name: "ListBuckets", Status: steps.StatusPass, Duration: 30 * time.Millisecond},
			{Name: "PutObject", Status: steps.StatusFail, Duration: 100 * time.Millisecond, Error: "403 Forbidden"},
		},
		Duration: 130 * time.Millisecond,
	}
	r.RenderStepResult("S3Validate", result)

	output := buf.String()
	if !strings.Contains(output, "ListBuckets") {
		t.Error("should display sub-step name ListBuckets")
	}
	if !strings.Contains(output, "PutObject") {
		t.Error("should display sub-step name PutObject")
	}
}

func TestPanelRendererError(t *testing.T) {
	var buf bytes.Buffer
	r := NewPanelRenderer(&buf)

	err := &steps.StepError{
		Err:         fmt.Errorf("access denied"),
		Hint:        "Check that the role trust policy includes your OIDC provider",
		Code:        "AccessDenied",
		HTTPStatus:  403,
		RawResponse: "<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>",
	}
	r.RenderStepError("STSAssume", err)

	output := buf.String()
	if !strings.Contains(output, "AccessDenied") {
		t.Error("should display error code")
	}
	if !strings.Contains(output, "trust policy") {
		t.Error("should display diagnostic hint")
	}
}

func TestPanelRendererSummary(t *testing.T) {
	var buf bytes.Buffer
	r := NewPanelRenderer(&buf)

	results := map[string]*steps.StepResult{
		"OktaDeviceAuth": {Title: "Okta Device Auth", Duration: 5 * time.Second},
		"TokenDecode":    {Title: "Token Decode", Duration: 2 * time.Millisecond},
		"STSAssume":      {Title: "STS Assume", Duration: 200 * time.Millisecond},
	}
	order := []string{"OktaDeviceAuth", "TokenDecode", "STSAssume"}
	r.RenderSummary(results, order)

	output := buf.String()
	if !strings.Contains(output, "Okta Device Auth") {
		t.Error("summary should list step names")
	}
}

func TestPanelRendererWarning(t *testing.T) {
	var buf bytes.Buffer
	r := NewPanelRenderer(&buf)
	r.RenderWarning("TLS verification disabled (--insecure)")

	output := buf.String()
	if !strings.Contains(output, "TLS verification disabled") {
		t.Error("should display warning text")
	}
}
