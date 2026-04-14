package steps

import (
	"net/http"
	"testing"
	"time"
)

func TestFlowContextInitialization(t *testing.T) {
	cfg := &Config{}
	client := &http.Client{}
	ctx := NewFlowContext(cfg, client)

	if ctx.Config != cfg {
		t.Error("Config not set")
	}
	if ctx.HTTPClient != client {
		t.Error("HTTPClient not set")
	}
	if ctx.IDToken != "" {
		t.Error("IDToken should be empty")
	}
}

func TestFieldCreation(t *testing.T) {
	f := Field{Label: "AccessKeyId", Value: "AKIA1234", Sensitive: false}
	if f.Label != "AccessKeyId" {
		t.Errorf("expected AccessKeyId, got %s", f.Label)
	}
	if f.Sensitive {
		t.Error("AccessKeyId should not be sensitive")
	}

	secret := Field{Label: "SecretAccessKey", Value: "wJalr...", Sensitive: true}
	if !secret.Sensitive {
		t.Error("SecretAccessKey should be sensitive")
	}
}

func TestStepResultWithSubSteps(t *testing.T) {
	result := &StepResult{
		Title: "S3 Validate",
		Fields: []Field{
			{Label: "Endpoint", Value: "https://fb-data.example.com"},
		},
		SubSteps: []SubStep{
			{Name: "ListBuckets", Status: StatusPass, Duration: 50 * time.Millisecond},
			{Name: "PutObject", Status: StatusFail, Duration: 120 * time.Millisecond, Error: "403 Forbidden"},
		},
		Duration: 170 * time.Millisecond,
	}

	if len(result.SubSteps) != 2 {
		t.Errorf("expected 2 substeps, got %d", len(result.SubSteps))
	}
	if result.SubSteps[0].Status != StatusPass {
		t.Error("ListBuckets should pass")
	}
	if result.SubSteps[1].Status != StatusFail {
		t.Error("PutObject should fail")
	}
}
