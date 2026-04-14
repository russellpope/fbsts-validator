package s3signer

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSignRequestSetsAuthorizationHeader(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://s3.example.com/", nil)

	creds := &Credentials{
		AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "session-token-value",
	}

	signTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	SignRequest(req, creds, "us-east-1", "s3", signTime)

	auth := req.Header.Get("Authorization")
	if auth == "" {
		t.Fatal("Authorization header should be set")
	}
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256") {
		t.Errorf("Authorization should start with AWS4-HMAC-SHA256, got: %s", auth[:30])
	}
	if !strings.Contains(auth, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("Authorization should contain access key ID")
	}
	if !strings.Contains(auth, "20240115") {
		t.Error("Authorization should contain date stamp")
	}
}

func TestSignRequestSetsSecurityTokenHeader(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://s3.example.com/", nil)

	creds := &Credentials{
		AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "my-session-token",
	}

	SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	token := req.Header.Get("X-Amz-Security-Token")
	if token != "my-session-token" {
		t.Errorf("X-Amz-Security-Token = %q, want my-session-token", token)
	}
}

func TestSignRequestNoSessionToken(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://s3.example.com/", nil)

	creds := &Credentials{
		AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	token := req.Header.Get("X-Amz-Security-Token")
	if token != "" {
		t.Error("X-Amz-Security-Token should not be set without session token")
	}
}

func TestSignRequestSetsDateHeader(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://s3.example.com/", nil)

	creds := &Credentials{
		AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	signTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	SignRequest(req, creds, "us-east-1", "s3", signTime)

	date := req.Header.Get("X-Amz-Date")
	if date != "20240615T103000Z" {
		t.Errorf("X-Amz-Date = %q, want 20240615T103000Z", date)
	}
}

func TestSignRequestWithPayload(t *testing.T) {
	body := strings.NewReader("test payload content")
	req, _ := http.NewRequest("PUT", "https://s3.example.com/bucket/key", body)

	creds := &Credentials{
		AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "token",
	}

	SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	auth := req.Header.Get("Authorization")
	if auth == "" {
		t.Fatal("Authorization should be set for PUT with body")
	}

	hash := req.Header.Get("X-Amz-Content-Sha256")
	if hash == "" {
		t.Fatal("X-Amz-Content-Sha256 should be set")
	}
	if hash == "UNSIGNED-PAYLOAD" {
		t.Error("payload hash should be computed, not unsigned")
	}
}

func TestSignRequestSetsHostHeader(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://s3.example.com/", nil)

	creds := &Credentials{
		AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	host := req.Header.Get("Host")
	if host != "s3.example.com" {
		t.Errorf("Host = %q, want s3.example.com", host)
	}
}
