package trustpolicy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// DecodedJWT holds the parsed parts of a JWT. Signature is not verified;
// signature validation is the consumer's responsibility (e.g., FlashBlade
// performs it during AssumeRoleWithWebIdentity).
type DecodedJWT struct {
	Token  string                 // original (whitespace-trimmed) token
	Header map[string]interface{} // parsed JOSE header
	Claims map[string]interface{} // parsed claims payload
}

// DecodeJWT parses a JWT string into its header and claims. It does NOT
// verify the signature.
func DecodeJWT(token string) (*DecodedJWT, error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 dot-separated parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT header: %w", err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT payload: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing JWT header JSON: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT payload JSON: %w", err)
	}

	return &DecodedJWT{Token: token, Header: header, Claims: claims}, nil
}

// DecodeJWTFile reads a JWT from a file and decodes it. Convenience wrapper.
func DecodeJWTFile(path string) (*DecodedJWT, error) {
	raw, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return DecodeJWT(string(raw))
}

// readFile is a package-level indirection over os.ReadFile to make
// DecodeJWTFile testable in the future if needed.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
