package trustpolicy

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestFromJWT(t *testing.T) {
	tok := makeJWT(t,
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{
			"iss":    "https://idp.example",
			"sub":    "user1",
			"aud":    "purestorage",
			"groups": []interface{}{"eng", "security"},
		},
	)

	in := Inputs{
		Token: tok,
		Resolver: &PrincipalResolver{
			FlagName:  "okta-for-object",
			ARNFormat: "aws",
		},
		Now: func() time.Time { return time.Unix(1713300000, 0) },
	}

	rule, err := FromJWT(in)
	if err != nil {
		t.Fatalf("FromJWT: %v", err)
	}
	if rule.Principal.Federated != "arn:aws:iam:::oidc-provider/okta-for-object" {
		t.Errorf("Principal = %q", rule.Principal.Federated)
	}
	if !strings.HasPrefix(rule.Name, "rule-user1-") {
		t.Errorf("Name = %q, want prefix rule-user1-", rule.Name)
	}
	// Three default conditions (aud, sub, groups) — no iss or azp in the JWT.
	if len(rule.Conditions) != 3 {
		t.Errorf("got %d conditions, want 3: %+v", len(rule.Conditions), rule.Conditions)
	}
}

func TestBuild_NoJWT(t *testing.T) {
	cond, _ := ParseCondition("jwt:aud=eq:purestorage")
	in := Inputs{
		Conditions: []Condition{*cond},
		Resolver: &PrincipalResolver{
			FlagName:  "okta-for-object",
			ARNFormat: "aws",
		},
		Now: func() time.Time { return time.Unix(1713300000, 0) },
	}
	rule, err := Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rule.Name != "rule-1713300000" {
		t.Errorf("Name = %q, want rule-1713300000", rule.Name)
	}
	if len(rule.Conditions) != 1 || rule.Conditions[0].Key != "jwt:aud" {
		t.Errorf("Conditions = %+v", rule.Conditions)
	}
}

func TestInteractive_AcceptDefaults(t *testing.T) {
	tok := makeJWT(t,
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{
			"iss": "https://idp.example",
			"aud": "purestorage",
		},
	)

	// recognizedClaims = {aud, sub, azp, groups}. iss is NOT in that set, so its
	// include-default is N. aud's default is Y. Prompt sequence:
	//   iss include? (default N) → blank or "n" → decline
	//   aud include? (default Y) → blank → accept
	//   aud operator? (default StringEquals) → blank → accept
	//   aud values? (default purestorage) → blank → keep
	input := "\n\n\n\n"

	in := Inputs{
		Token:    tok,
		Resolver: &PrincipalResolver{FlagName: "okta-for-object", ARNFormat: "aws"},
		Now:      func() time.Time { return time.Unix(1713300000, 0) },
		Reader:   bufio.NewReader(strings.NewReader(input)),
		Writer:   &bytes.Buffer{},
	}
	rule, err := Interactive(in)
	if err != nil {
		t.Fatalf("Interactive: %v", err)
	}
	if len(rule.Conditions) != 1 || rule.Conditions[0].Key != "jwt:aud" {
		t.Errorf("Conditions = %+v", rule.Conditions)
	}
}

func TestFromJWT_ExtraConditions(t *testing.T) {
	tok := makeJWT(t,
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{"sub": "user1", "aud": "purestorage"},
	)
	cond, _ := ParseCondition("aws:SourceIp=ip:10.0.0.0/8")
	in := Inputs{
		Token:      tok,
		Conditions: []Condition{*cond},
		Resolver:   &PrincipalResolver{FlagName: "x", ARNFormat: "aws"},
		Now:        func() time.Time { return time.Unix(1713300000, 0) },
	}
	rule, err := FromJWT(in)
	if err != nil {
		t.Fatalf("FromJWT: %v", err)
	}
	// 2 from JWT (aud, sub) + 1 from --condition flag = 3
	if len(rule.Conditions) != 3 {
		t.Errorf("got %d conditions, want 3: %+v", len(rule.Conditions), rule.Conditions)
	}
}
