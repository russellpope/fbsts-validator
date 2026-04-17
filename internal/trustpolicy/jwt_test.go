package trustpolicy

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func makeJWT(t *testing.T, header, claims map[string]interface{}) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc(h) + "." + enc(c) + ".fakesignature"
}

func TestDecodeJWT_HappyPath(t *testing.T) {
	tok := makeJWT(t,
		map[string]interface{}{"alg": "RS256", "kid": "abc"},
		map[string]interface{}{"iss": "https://idp.example", "sub": "user1", "aud": "purestorage", "groups": []interface{}{"eng", "security"}},
	)

	got, err := DecodeJWT(tok)
	if err != nil {
		t.Fatalf("DecodeJWT: %v", err)
	}

	if got.Header["alg"] != "RS256" {
		t.Errorf("Header[alg] = %v, want RS256", got.Header["alg"])
	}
	if got.Claims["iss"] != "https://idp.example" {
		t.Errorf("Claims[iss] = %v, want https://idp.example", got.Claims["iss"])
	}
	if got.Token != tok {
		t.Errorf("Token roundtrip mismatch")
	}
}

func TestDecodeJWT_Errors(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string // substring expected in error
	}{
		{"two parts", "a.b", "expected 3"},
		{"four parts", "a.b.c.d", "expected 3"},
		{"bad base64 header", "!!!.eyJhIjoxfQ.sig", "header"},
		{"bad base64 payload", "eyJhIjoxfQ.!!!.sig", "payload"},
		{"non-json header", base64.RawURLEncoding.EncodeToString([]byte("notjson")) + ".eyJhIjoxfQ.sig", "header"},
		{"non-json payload", "eyJhIjoxfQ." + base64.RawURLEncoding.EncodeToString([]byte("notjson")) + ".sig", "payload"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeJWT(tc.token)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestDecodeJWT_TrimsWhitespace(t *testing.T) {
	tok := makeJWT(t,
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{"sub": "user1"},
	)
	got, err := DecodeJWT("  " + tok + "\n")
	if err != nil {
		t.Fatalf("DecodeJWT: %v", err)
	}
	if got.Claims["sub"] != "user1" {
		t.Errorf("Claims[sub] = %v, want user1", got.Claims["sub"])
	}
}
