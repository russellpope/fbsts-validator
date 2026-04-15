package steps

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pure-experimental/rp-fbstsvalidator/internal/s3signer"
)

// S3ValidateStep performs a CRUD cycle against an S3-compatible endpoint
// using STS credentials to verify they work end-to-end.
type S3ValidateStep struct{}

// NewS3ValidateStep returns a new S3ValidateStep.
func NewS3ValidateStep() *S3ValidateStep {
	return &S3ValidateStep{}
}

// Name returns the step name used by the runner and renderer.
func (s *S3ValidateStep) Name() string {
	return "S3Validate"
}

// Execute performs ListBuckets, PutObject, GetObject, and DeleteObject
// against the configured S3 endpoint using STS credentials from ctx.
func (s *S3ValidateStep) Execute(ctx *FlowContext) (*StepResult, error) {
	if ctx.AccessKeyId == "" || ctx.SecretAccessKey == "" {
		return nil, &StepError{
			Err:  fmt.Errorf("no STS credentials present"),
			Hint: "The STSAssume step must run before S3Validate to supply credentials.",
		}
	}

	creds := &s3signer.Credentials{
		AccessKeyId:     ctx.AccessKeyId,
		SecretAccessKey: ctx.SecretAccessKey,
		SessionToken:    ctx.SessionToken,
	}

	endpoint := ctx.Config.DataEndpoint
	bucket := ctx.Config.TestBucket
	key := fmt.Sprintf("%s%d.txt", ctx.Config.TestKeyPrefix, time.Now().UnixNano())

	client := ctx.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	var subSteps []SubStep
	putOK := false

	// --- ListBuckets (independent) ---
	listSub, _ := doListBuckets(client, creds, endpoint)
	subSteps = append(subSteps, listSub)

	// --- PutObject ---
	content := []byte("rp-fbstsvalidator test object " + time.Now().UTC().Format(time.RFC3339))
	putSub, putErr := doPutObject(client, creds, endpoint, bucket, key, content)
	subSteps = append(subSteps, putSub)
	if putErr == nil {
		putOK = true
	}

	// --- GetObject (depends on PutObject) ---
	if putOK {
		getSub, _ := doGetObject(client, creds, endpoint, bucket, key, content)
		subSteps = append(subSteps, getSub)
	} else {
		subSteps = append(subSteps, SubStep{
			Name:   "GetObject",
			Status: StatusFail,
			Error:  "skipped — PutObject failed",
		})
	}

	// --- DeleteObject (depends on PutObject) ---
	if putOK {
		delSub, _ := doDeleteObject(client, creds, endpoint, bucket, key)
		subSteps = append(subSteps, delSub)
	} else {
		subSteps = append(subSteps, SubStep{
			Name:   "DeleteObject",
			Status: StatusFail,
			Error:  "skipped — PutObject failed",
		})
	}

	ctx.S3Results = buildS3Results(subSteps, bucket, key)

	return &StepResult{
		Title: "S3 Validate",
		Fields: []Field{
			{Label: "endpoint", Value: endpoint},
			{Label: "bucket", Value: bucket},
			{Label: "key", Value: key},
		},
		SubSteps: subSteps,
	}, nil
}

// doListBuckets performs GET {endpoint}/ and returns a SubStep result.
func doListBuckets(client *http.Client, creds *s3signer.Credentials, endpoint string) (SubStep, error) {
	start := time.Now()

	req, err := http.NewRequest("GET", endpoint+"/", nil)
	if err != nil {
		sub := SubStep{
			Name:     "ListBuckets",
			Status:   StatusFail,
			Duration: time.Since(start),
			Error:    err.Error(),
		}
		return sub, &StepError{Err: fmt.Errorf("ListBuckets request build failed: %w", err)}
	}

	s3signer.SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	resp, err := client.Do(req)
	dur := time.Since(start)
	if err != nil {
		sub := SubStep{
			Name:     "ListBuckets",
			Status:   StatusFail,
			Duration: dur,
			Error:    err.Error(),
		}
		return sub, &StepError{Err: fmt.Errorf("ListBuckets request failed: %w", err)}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("ListBuckets returned HTTP %d", resp.StatusCode)
		sub := SubStep{
			Name:     "ListBuckets",
			Status:   StatusFail,
			Duration: dur,
			Error:    msg,
			Fields:   []Field{{Label: "http_status", Value: fmt.Sprintf("%d", resp.StatusCode)}},
		}
		return sub, &StepError{
			Err:        fmt.Errorf("%s", msg),
			HTTPStatus: resp.StatusCode,
		}
	}

	sub := SubStep{
		Name:     "ListBuckets",
		Status:   StatusPass,
		Duration: dur,
		Fields:   []Field{{Label: "http_status", Value: fmt.Sprintf("%d", resp.StatusCode)}},
	}
	return sub, nil
}

// doPutObject performs PUT {endpoint}/{bucket}/{key} with the given content.
func doPutObject(client *http.Client, creds *s3signer.Credentials, endpoint, bucket, key string, content []byte) (SubStep, error) {
	start := time.Now()

	url := fmt.Sprintf("%s/%s/%s", endpoint, bucket, key)
	req, err := http.NewRequest("PUT", url, bytes.NewReader(content))
	if err != nil {
		sub := SubStep{
			Name:     "PutObject",
			Status:   StatusFail,
			Duration: time.Since(start),
			Error:    err.Error(),
		}
		return sub, &StepError{Err: fmt.Errorf("PutObject request build failed: %w", err)}
	}

	s3signer.SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	resp, err := client.Do(req)
	dur := time.Since(start)
	if err != nil {
		sub := SubStep{
			Name:     "PutObject",
			Status:   StatusFail,
			Duration: dur,
			Error:    err.Error(),
		}
		return sub, &StepError{Err: fmt.Errorf("PutObject request failed: %w", err)}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("PutObject returned HTTP %d", resp.StatusCode)
		sub := SubStep{
			Name:     "PutObject",
			Status:   StatusFail,
			Duration: dur,
			Error:    msg,
			Fields:   []Field{{Label: "http_status", Value: fmt.Sprintf("%d", resp.StatusCode)}},
		}
		return sub, &StepError{
			Err:        fmt.Errorf("%s", msg),
			HTTPStatus: resp.StatusCode,
		}
	}

	sub := SubStep{
		Name:     "PutObject",
		Status:   StatusPass,
		Duration: dur,
		Fields: []Field{
			{Label: "http_status", Value: fmt.Sprintf("%d", resp.StatusCode)},
			{Label: "bytes", Value: fmt.Sprintf("%d", len(content))},
		},
	}
	return sub, nil
}

// doGetObject performs GET {endpoint}/{bucket}/{key} and verifies content hash.
func doGetObject(client *http.Client, creds *s3signer.Credentials, endpoint, bucket, key string, expectedContent []byte) (SubStep, error) {
	start := time.Now()

	url := fmt.Sprintf("%s/%s/%s", endpoint, bucket, key)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		sub := SubStep{
			Name:     "GetObject",
			Status:   StatusFail,
			Duration: time.Since(start),
			Error:    err.Error(),
		}
		return sub, &StepError{Err: fmt.Errorf("GetObject request build failed: %w", err)}
	}

	s3signer.SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	resp, err := client.Do(req)
	dur := time.Since(start)
	if err != nil {
		sub := SubStep{
			Name:     "GetObject",
			Status:   StatusFail,
			Duration: dur,
			Error:    err.Error(),
		}
		return sub, &StepError{Err: fmt.Errorf("GetObject request failed: %w", err)}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	dur = time.Since(start)
	if err != nil {
		sub := SubStep{
			Name:     "GetObject",
			Status:   StatusFail,
			Duration: dur,
			Error:    fmt.Sprintf("reading response body: %v", err),
		}
		return sub, &StepError{Err: fmt.Errorf("GetObject body read failed: %w", err)}
	}

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("GetObject returned HTTP %d", resp.StatusCode)
		sub := SubStep{
			Name:     "GetObject",
			Status:   StatusFail,
			Duration: dur,
			Error:    msg,
			Fields:   []Field{{Label: "http_status", Value: fmt.Sprintf("%d", resp.StatusCode)}},
		}
		return sub, &StepError{
			Err:        fmt.Errorf("%s", msg),
			HTTPStatus: resp.StatusCode,
		}
	}

	// Verify content hash only when we have expected content to compare against.
	gotHash := sha256Hash(body)
	fields := []Field{
		{Label: "http_status", Value: fmt.Sprintf("%d", resp.StatusCode)},
		{Label: "sha256", Value: gotHash},
	}

	if len(expectedContent) > 0 {
		wantHash := sha256Hash(expectedContent)
		if gotHash != wantHash {
			msg := fmt.Sprintf("content hash mismatch: got %s, want %s", gotHash, wantHash)
			sub := SubStep{
				Name:     "GetObject",
				Status:   StatusFail,
				Duration: dur,
				Error:    msg,
				Fields:   fields,
			}
			return sub, &StepError{Err: fmt.Errorf("%s", msg)}
		}
	}

	sub := SubStep{
		Name:     "GetObject",
		Status:   StatusPass,
		Duration: dur,
		Fields:   fields,
	}
	return sub, nil
}

// doDeleteObject performs DELETE {endpoint}/{bucket}/{key}.
func doDeleteObject(client *http.Client, creds *s3signer.Credentials, endpoint, bucket, key string) (SubStep, error) {
	start := time.Now()

	url := fmt.Sprintf("%s/%s/%s", endpoint, bucket, key)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		sub := SubStep{
			Name:     "DeleteObject",
			Status:   StatusFail,
			Duration: time.Since(start),
			Error:    err.Error(),
		}
		return sub, &StepError{Err: fmt.Errorf("DeleteObject request build failed: %w", err)}
	}

	s3signer.SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	resp, err := client.Do(req)
	dur := time.Since(start)
	if err != nil {
		sub := SubStep{
			Name:     "DeleteObject",
			Status:   StatusFail,
			Duration: dur,
			Error:    err.Error(),
		}
		return sub, &StepError{Err: fmt.Errorf("DeleteObject request failed: %w", err)}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		msg := fmt.Sprintf("DeleteObject returned HTTP %d", resp.StatusCode)
		sub := SubStep{
			Name:     "DeleteObject",
			Status:   StatusFail,
			Duration: dur,
			Error:    msg,
			Fields:   []Field{{Label: "http_status", Value: fmt.Sprintf("%d", resp.StatusCode)}},
		}
		return sub, &StepError{
			Err:        fmt.Errorf("%s", msg),
			HTTPStatus: resp.StatusCode,
		}
	}

	sub := SubStep{
		Name:     "DeleteObject",
		Status:   StatusPass,
		Duration: dur,
		Fields:   []Field{{Label: "http_status", Value: fmt.Sprintf("%d", resp.StatusCode)}},
	}
	return sub, nil
}

// sha256Hash returns the lowercase hex-encoded SHA-256 hash of data.
func sha256Hash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// buildS3Results converts substeps into S3OpResult records for ctx.S3Results.
func buildS3Results(subSteps []SubStep, bucket, key string) []S3OpResult {
	results := make([]S3OpResult, 0, len(subSteps))
	for _, ss := range subSteps {
		r := S3OpResult{
			Operation: ss.Name,
			Bucket:    bucket,
			Key:       key,
			Pass:      ss.Status == StatusPass,
			Duration:  ss.Duration,
			Error:     ss.Error,
		}
		// Extract http_status field if present.
		for _, f := range ss.Fields {
			if f.Label == "http_status" {
				fmt.Sscanf(f.Value, "%d", &r.HTTPStatus)
				break
			}
		}
		results = append(results, r)
	}
	return results
}
