package render

import "testing"

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "**********"},
		{"short", "**********"},
		{"", "**********"},
	}
	for _, tt := range tests {
		got := MaskSecret(tt.input)
		if got != tt.expected {
			t.Errorf("MaskSecret(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestTruncateJWT(t *testing.T) {
	// A fake JWT with three dot-separated parts
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Signature_Bytes_Here"
	result := TruncateJWT(jwt)

	// Should contain the header, a masked middle, and a signature hint
	if len(result) >= len(jwt) {
		t.Errorf("TruncateJWT should shorten the token, got len %d vs original %d", len(result), len(jwt))
	}
	if result[:10] != jwt[:10] {
		t.Error("TruncateJWT should preserve the start of the header")
	}
	if !contains(result, "<masked>") {
		t.Error("TruncateJWT should contain <masked> placeholder")
	}
}

func TestTruncateJWTInvalid(t *testing.T) {
	// Not a valid JWT (no dots)
	result := TruncateJWT("not-a-jwt")
	if result != "not-a-jwt" {
		t.Errorf("TruncateJWT should return non-JWTs unchanged, got %q", result)
	}
}

func TestTruncateToken(t *testing.T) {
	token := "FwoGZXIvYXdzEBYaDHQqX0123456789abcdef0123456789abcdef"
	result := TruncateToken(token, 20, 6)

	if len(result) >= len(token) {
		t.Errorf("TruncateToken should shorten the token")
	}
	// First 20 chars preserved
	if result[:20] != token[:20] {
		t.Error("TruncateToken should preserve prefix")
	}
	// Last 6 chars preserved
	if result[len(result)-6:] != token[len(token)-6:] {
		t.Error("TruncateToken should preserve suffix")
	}
	if !contains(result, "...") {
		t.Error("TruncateToken should contain ellipsis")
	}
}

func TestTruncateTokenShort(t *testing.T) {
	// Token shorter than prefix+suffix — return unchanged
	result := TruncateToken("short", 20, 6)
	if result != "short" {
		t.Errorf("TruncateToken should return short tokens unchanged, got %q", result)
	}
}

func TestMaskField(t *testing.T) {
	// Non-sensitive field returned as-is
	val := MaskField("AKIAIOSFODNN7EXAMPLE", false)
	if val != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("non-sensitive field should be unchanged, got %q", val)
	}

	// Sensitive field masked
	val = MaskField("wJalrXUtnFEMI", true)
	if val != "**********" {
		t.Errorf("sensitive field should be masked, got %q", val)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
