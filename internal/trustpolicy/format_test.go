package trustpolicy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func sampleRule() *Rule {
	return &Rule{
		Name:      "rule-user123-1713300000",
		Effect:    "allow",
		Principal: Principal{Federated: "arn:aws:iam:::oidc-provider/okta-for-object"},
		Action:    "sts:AssumeRoleWithWebIdentity",
		Conditions: []Condition{
			{Operator: "StringEquals", Key: "jwt:aud", Values: []string{"purestorage"}},
			{Operator: "ForAnyValue:StringEquals", Key: "jwt:groups", Values: []string{"eng", "security"}},
		},
	}
}

func TestEncodeRuleBody(t *testing.T) {
	out, err := EncodeRuleBody(sampleRule())
	if err != nil {
		t.Fatalf("EncodeRuleBody: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, string(out))
	}

	want := map[string]interface{}{
		"name":   "rule-user123-1713300000",
		"effect": "allow",
		"principal": map[string]interface{}{
			"federated": "arn:aws:iam:::oidc-provider/okta-for-object",
		},
		"action": "sts:AssumeRoleWithWebIdentity",
		"conditions": []interface{}{
			map[string]interface{}{
				"operator": "StringEquals",
				"key":      "jwt:aud",
				"values":   []interface{}{"purestorage"},
			},
			map[string]interface{}{
				"operator": "ForAnyValue:StringEquals",
				"key":      "jwt:groups",
				"values":   []interface{}{"eng", "security"},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("EncodeRuleBody mismatch\ngot:  %+v\nwant: %+v", got, want)
	}
}

func TestEncodeIAMDocument_SingleStatement(t *testing.T) {
	out, err := EncodeIAMDocument([]Rule{*sampleRule()})
	if err != nil {
		t.Fatalf("EncodeIAMDocument: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, string(out))
	}

	if got["Version"] != "2012-10-17" {
		t.Errorf("Version = %v, want 2012-10-17", got["Version"])
	}
	stmts, ok := got["Statement"].([]interface{})
	if !ok || len(stmts) != 1 {
		t.Fatalf("Statement = %v, want one-element array", got["Statement"])
	}
	s := stmts[0].(map[string]interface{})

	if s["Sid"] != "ruleuser1231713300000" {
		t.Errorf("Sid = %v, want sanitized ruleuser1231713300000", s["Sid"])
	}
	if s["Effect"] != "Allow" {
		t.Errorf("Effect = %v, want Allow (TitleCase)", s["Effect"])
	}
	principal := s["Principal"].(map[string]interface{})
	if principal["Federated"] != "arn:aws:iam:::oidc-provider/okta-for-object" {
		t.Errorf("Principal.Federated = %v", principal["Federated"])
	}
	if s["Action"] != "sts:AssumeRoleWithWebIdentity" {
		t.Errorf("Action = %v", s["Action"])
	}

	cond := s["Condition"].(map[string]interface{})
	if cond["StringEquals"].(map[string]interface{})["jwt:aud"] != "purestorage" {
		t.Errorf("StringEquals.jwt:aud = %v", cond["StringEquals"])
	}
	gv := cond["ForAnyValue:StringEquals"].(map[string]interface{})["jwt:groups"]
	gvSlice, ok := gv.([]interface{})
	if !ok || len(gvSlice) != 2 || gvSlice[0] != "eng" || gvSlice[1] != "security" {
		t.Errorf("ForAnyValue:StringEquals.jwt:groups = %v", gv)
	}
}

func TestEncodeIAMDocument_DenyEffectTitleCase(t *testing.T) {
	r := sampleRule()
	r.Effect = "deny"
	out, _ := EncodeIAMDocument([]Rule{*r})
	if !strings.Contains(string(out), `"Effect": "Deny"`) {
		t.Errorf("expected `\"Effect\": \"Deny\"` in IAM output:\n%s", string(out))
	}
}

func TestSanitizeSid(t *testing.T) {
	tests := map[string]string{
		"rule-abc-123":           "ruleabc123",
		"user@example.com":       "userexamplecom",
		"only_alpha":             "onlyalpha",
		"":                       "",
		"---":                    "",
		"abc123":                 "abc123",
	}
	for in, want := range tests {
		t.Run(in, func(t *testing.T) {
			if got := sanitizeSid(in); got != want {
				t.Errorf("sanitizeSid(%q) = %q, want %q", in, got, want)
			}
		})
	}
}
