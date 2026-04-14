package render

import "strings"

// MaskSecret replaces any value with asterisks. Used for SecretAccessKey, passwords.
func MaskSecret(value string) string {
	return "**********"
}

// TruncateJWT shows the header portion, masks the payload, and shows a signature hint.
// Input format: header.payload.signature
// Output format: eyJhbGci...<masked>...kF9xQ
func TruncateJWT(jwt string) string {
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		return jwt
	}

	header := parts[0]
	sig := parts[2]

	// Show first 10 chars of header, last 5 of signature
	headerHint := header
	if len(header) > 10 {
		headerHint = header[:10]
	}
	sigHint := sig
	if len(sig) > 5 {
		sigHint = sig[len(sig)-5:]
	}

	return headerHint + "...<masked>..." + sigHint
}

// TruncateToken shows the first `prefix` and last `suffix` characters with an ellipsis in between.
// If the token is shorter than prefix+suffix+3, it is returned unchanged.
func TruncateToken(token string, prefix, suffix int) string {
	if len(token) <= prefix+suffix+3 {
		return token
	}
	return token[:prefix] + "..." + token[len(token)-suffix:]
}

// MaskField returns the value masked or unchanged based on the sensitive flag.
func MaskField(value string, sensitive bool) string {
	if sensitive {
		return MaskSecret(value)
	}
	return value
}
