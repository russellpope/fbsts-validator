package steps

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSTSAssumeStepName(t *testing.T) {
	step := NewSTSAssumeStep()
	if step.Name() != "STSAssume" {
		t.Errorf("Name() = %q, want STSAssume", step.Name())
	}
}

func TestSTSAssumeSuccess(t *testing.T) {
	const (
		wantRoleARN          = "arn:aws:iam::123456789:role/test-role"
		wantWebIdentityToken = "eyJ0ZXN0dG9rZW4iOiJ0cnVlIn0.test.sig"
	)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if got := r.FormValue("Action"); got != "AssumeRoleWithWebIdentity" {
			t.Errorf("Action = %q, want AssumeRoleWithWebIdentity", got)
		}
		if got := r.FormValue("Version"); got != "2011-06-15" {
			t.Errorf("Version = %q, want 2011-06-15", got)
		}
		if got := r.FormValue("RoleArn"); got != wantRoleARN {
			t.Errorf("RoleArn = %q, want %q", got, wantRoleARN)
		}
		if got := r.FormValue("WebIdentityToken"); got != wantWebIdentityToken {
			t.Errorf("WebIdentityToken = %q, want %q", got, wantWebIdentityToken)
		}

		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIATESTACCESSKEY</AccessKeyId>
      <SecretAccessKey>testsecretkey123456</SecretAccessKey>
      <SessionToken>FwoGZXIvYXdzTestSessionToken</SessionToken>
      <Expiration>2024-01-15T13:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789:assumed-role/test-role/fbsts-validate</Arn>
      <AssumedRoleId>AROATESTROLE:fbsts-validate</AssumedRoleId>
    </AssumedRoleUser>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`)
	}))
	defer server.Close()

	// Use the TLS server's own client so its self-signed cert is trusted.
	ctx := NewFlowContext(&Config{
		STSEndpoint: server.URL,
		RoleARN:     wantRoleARN,
		Duration:    900,
	}, tlsTestClient(server))
	ctx.IDToken = wantWebIdentityToken

	step := NewSTSAssumeStep()
	result, err := step.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}

	if ctx.AccessKeyId != "ASIATESTACCESSKEY" {
		t.Errorf("AccessKeyId = %q, want ASIATESTACCESSKEY", ctx.AccessKeyId)
	}
	if ctx.SecretAccessKey != "testsecretkey123456" {
		t.Errorf("SecretAccessKey = %q, want testsecretkey123456", ctx.SecretAccessKey)
	}
	if ctx.SessionToken != "FwoGZXIvYXdzTestSessionToken" {
		t.Errorf("SessionToken = %q, want FwoGZXIvYXdzTestSessionToken", ctx.SessionToken)
	}
	if ctx.AssumedRoleARN != "arn:aws:sts::123456789:assumed-role/test-role/fbsts-validate" {
		t.Errorf("AssumedRoleARN = %q", ctx.AssumedRoleARN)
	}

	// Verify SecretAccessKey field is marked Sensitive.
	var foundSecret bool
	for _, f := range result.Fields {
		if f.Label == "SecretAccessKey" {
			foundSecret = true
			if !f.Sensitive {
				t.Error("SecretAccessKey field should be Sensitive")
			}
		}
	}
	if !foundSecret {
		t.Error("SecretAccessKey field not found in result")
	}
}

func TestSTSAssumeAccessDenied(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>AccessDenied</Code><Message>Not authorized</Message></Error>
</ErrorResponse>`)
	}))
	defer server.Close()

	ctx := NewFlowContext(&Config{
		STSEndpoint: server.URL,
		RoleARN:     "arn:aws:iam::123456789:role/test-role",
	}, tlsTestClient(server))
	ctx.IDToken = "some.token.here"

	step := NewSTSAssumeStep()
	_, err := step.Execute(ctx)
	if err == nil {
		t.Fatal("expected error for 403 response")
	}

	stepErr, ok := err.(*StepError)
	if !ok {
		t.Fatalf("expected *StepError, got %T", err)
	}
	if stepErr.Code != "AccessDenied" {
		t.Errorf("Code = %q, want AccessDenied", stepErr.Code)
	}
	if stepErr.HTTPStatus != http.StatusForbidden {
		t.Errorf("HTTPStatus = %d, want 403", stepErr.HTTPStatus)
	}
}

func TestSTSAssumeNoToken(t *testing.T) {
	ctx := NewFlowContext(&Config{
		STSEndpoint: "https://sts.example.com",
		RoleARN:     "arn:aws:iam::123456789:role/test-role",
	}, &http.Client{})
	// IDToken intentionally left empty.

	step := NewSTSAssumeStep()
	_, err := step.Execute(ctx)
	if err == nil {
		t.Fatal("expected error when IDToken is empty")
	}
}

// tlsTestClient returns an *http.Client that trusts the TLS certificate of the
// given httptest.Server.
func tlsTestClient(server *httptest.Server) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// server.Client() returns a pre-configured client for the test server,
				// but we need to extract the transport from it.
				RootCAs: server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
			},
		},
	}
}
