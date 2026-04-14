package steps

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestS3ValidateStepName(t *testing.T) {
	step := NewS3ValidateStep()
	if step.Name() != "S3Validate" {
		t.Errorf("Name() = %q, want S3Validate", step.Name())
	}
}

func TestS3ValidateSuccess(t *testing.T) {
	// stored holds the body written by PUT so GET can return it.
	var mu sync.Mutex
	stored := map[string][]byte{}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// ListBuckets: GET /
		case r.Method == "GET" && path == "/":
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult></ListAllMyBucketsResult>`)

		// PutObject: PUT /test-bucket/<key>
		case r.Method == "PUT" && strings.HasPrefix(path, "/test-bucket/"):
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			stored[path] = body
			mu.Unlock()
			w.WriteHeader(http.StatusOK)

		// GetObject: GET /test-bucket/<key>
		case r.Method == "GET" && strings.HasPrefix(path, "/test-bucket/"):
			mu.Lock()
			body, ok := stored[path]
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write(body)

		// DeleteObject: DELETE /test-bucket/<key>
		case r.Method == "DELETE" && strings.HasPrefix(path, "/test-bucket/"):
			mu.Lock()
			delete(stored, path)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "unexpected request", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := &Config{
		DataEndpoint:  server.URL,
		TestBucket:    "test-bucket",
		TestKeyPrefix: "test-",
	}
	ctx := NewFlowContext(cfg, server.Client())
	ctx.AccessKeyId = "AKIAIOSFODNN7EXAMPLE"
	ctx.SecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	ctx.SessionToken = "test-session-token"

	step := NewS3ValidateStep()
	result, err := step.Execute(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if len(result.SubSteps) != 4 {
		t.Fatalf("expected 4 SubSteps, got %d", len(result.SubSteps))
	}

	names := []string{"ListBuckets", "PutObject", "GetObject", "DeleteObject"}
	for i, name := range names {
		if result.SubSteps[i].Name != name {
			t.Errorf("SubStep[%d].Name = %q, want %q", i, result.SubSteps[i].Name, name)
		}
		if result.SubSteps[i].Status != StatusPass {
			t.Errorf("SubStep[%d] (%s) Status = %v, want StatusPass; error: %s",
				i, name, result.SubSteps[i].Status, result.SubSteps[i].Error)
		}
	}

	// Verify ctx.S3Results is populated.
	if len(ctx.S3Results) != 4 {
		t.Errorf("expected 4 S3Results, got %d", len(ctx.S3Results))
	}
	for _, r := range ctx.S3Results {
		if !r.Pass {
			t.Errorf("S3OpResult %s should be Pass", r.Operation)
		}
	}
}

func TestS3ValidatePutForbidden(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/":
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult></ListAllMyBucketsResult>`)
		case r.Method == "PUT":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := &Config{
		DataEndpoint:    server.URL,
		TestBucket:      "test-bucket",
		TestKeyPrefix:   "test-",
		ContinueOnError: false,
	}
	ctx := NewFlowContext(cfg, server.Client())
	ctx.AccessKeyId = "AKIAIOSFODNN7EXAMPLE"
	ctx.SecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	ctx.SessionToken = "test-session-token"

	step := NewS3ValidateStep()
	_, err := step.Execute(ctx)

	if err == nil {
		t.Fatal("expected error when PUT returns 403")
	}
}

func TestS3ValidateNoCreds(t *testing.T) {
	cfg := &Config{
		DataEndpoint:  "https://fb-data.example.com",
		TestBucket:    "test-bucket",
		TestKeyPrefix: "test-",
	}
	ctx := NewFlowContext(cfg, http.DefaultClient)
	// Deliberately leave AccessKeyId and SecretAccessKey empty.

	step := NewS3ValidateStep()
	_, err := step.Execute(ctx)

	if err == nil {
		t.Fatal("expected error when no credentials are set")
	}
}
