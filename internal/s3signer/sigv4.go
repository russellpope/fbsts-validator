package s3signer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Credentials holds AWS credentials used for SigV4 signing.
type Credentials struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
}

// SignRequest signs an HTTP request in place using AWS SigV4.
// It sets Host, X-Amz-Date, X-Amz-Content-Sha256, and Authorization headers.
// If SessionToken is non-empty, X-Amz-Security-Token is also set.
func SignRequest(req *http.Request, creds *Credentials, region, service string, signTime time.Time) {
	dateStamp := signTime.Format("20060102")
	amzDate := signTime.Format("20060102T150405Z")

	// Set Host header
	host := req.URL.Host
	req.Header.Set("Host", host)

	// Set date header
	req.Header.Set("X-Amz-Date", amzDate)

	// Set security token if present
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	// Compute payload hash
	payloadHash := hashPayload(req)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	// Build canonical request
	canonicalRequest, signedHeaders := buildCanonicalRequest(req, payloadHash)

	// Build string to sign
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	// Derive signing key
	signingKey := deriveSigningKey(creds.SecretAccessKey, dateStamp, region, service)

	// Compute signature
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// Build Authorization header
	auth := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyId, credentialScope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", auth)
}

// hashPayload reads the request body, hashes it with SHA256, then resets the body.
// Returns the lowercase hex-encoded hash.
func hashPayload(req *http.Request) string {
	if req.Body == nil {
		return hexSHA256([]byte{})
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return hexSHA256([]byte{})
	}
	req.Body = io.NopCloser(strings.NewReader(string(body)))
	return hexSHA256(body)
}

// buildCanonicalRequest constructs the AWS canonical request string and returns
// the canonical request along with the sorted, semicolon-delimited signed headers list.
func buildCanonicalRequest(req *http.Request, payloadHash string) (string, string) {
	method := req.Method

	// Canonical URI: percent-encode the path, preserve slashes
	canonicalURI := canonicalizeURI(req.URL)

	// Canonical query string
	canonicalQueryString := canonicalizeQueryString(req.URL)

	// Canonical headers and signed headers list
	canonicalHeaders, signedHeaders := canonicalizeHeaders(req)

	canonicalRequest := strings.Join([]string{
		method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	return canonicalRequest, signedHeaders
}

// canonicalizeURI returns the URI-encoded path component per SigV4 rules.
func canonicalizeURI(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

// canonicalizeQueryString returns the sorted, encoded query string per SigV4 rules.
func canonicalizeQueryString(u *url.URL) string {
	vals := u.Query()
	if len(vals) == 0 {
		return ""
	}

	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		vs := vals[k]
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

// canonicalizeHeaders returns the canonical headers block (with trailing newline)
// and the semicolon-delimited signed headers string, both sorted by header name.
func canonicalizeHeaders(req *http.Request) (string, string) {
	// Collect headers to sign: all headers present plus host
	headers := make(map[string]string)

	// Include Host from the header we already set
	if host := req.Header.Get("Host"); host != "" {
		headers["host"] = host
	}

	for k, vv := range req.Header {
		lk := strings.ToLower(k)
		if lk == "host" {
			// already handled
			continue
		}
		headers[lk] = strings.TrimSpace(strings.Join(vv, ","))
	}

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canonParts []string
	for _, k := range keys {
		canonParts = append(canonParts, k+":"+headers[k])
	}

	// Canonical headers block ends with a newline
	canonicalHeaders := strings.Join(canonParts, "\n") + "\n"
	signedHeaders := strings.Join(keys, ";")

	return canonicalHeaders, signedHeaders
}

// deriveSigningKey derives the SigV4 signing key via the HMAC chain:
// HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")
func deriveSigningKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

// hmacSHA256 computes HMAC-SHA256 of data using key.
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// hexSHA256 returns the lowercase hex-encoded SHA256 hash of data.
func hexSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
