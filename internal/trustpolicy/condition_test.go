package trustpolicy

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseCondition_Shortcuts(t *testing.T) {
	tests := []struct {
		dsl  string
		want Condition
	}{
		{"jwt:aud=eq:purestorage", Condition{Operator: "StringEquals", Key: "jwt:aud", Values: []string{"purestorage"}}},
		{"jwt:sub=neq:bob", Condition{Operator: "StringNotEquals", Key: "jwt:sub", Values: []string{"bob"}}},
		{"jwt:sub=like:user-*", Condition{Operator: "StringLike", Key: "jwt:sub", Values: []string{"user-*"}}},
		{"jwt:sub=nlike:guest-*", Condition{Operator: "StringNotLike", Key: "jwt:sub", Values: []string{"guest-*"}}},
		{"sts:DurationSeconds=num-eq:3600", Condition{Operator: "NumericEquals", Key: "sts:DurationSeconds", Values: []string{"3600"}}},
		{"sts:DurationSeconds=num-neq:0", Condition{Operator: "NumericNotEquals", Key: "sts:DurationSeconds", Values: []string{"0"}}},
		{"sts:DurationSeconds=lt:3600", Condition{Operator: "NumericLessThan", Key: "sts:DurationSeconds", Values: []string{"3600"}}},
		{"sts:DurationSeconds=lte:3600", Condition{Operator: "NumericLessThanEquals", Key: "sts:DurationSeconds", Values: []string{"3600"}}},
		{"sts:DurationSeconds=gt:60", Condition{Operator: "NumericGreaterThan", Key: "sts:DurationSeconds", Values: []string{"60"}}},
		{"sts:DurationSeconds=gte:60", Condition{Operator: "NumericGreaterThanEquals", Key: "sts:DurationSeconds", Values: []string{"60"}}},
		{"aws:SourceIp=ip:10.0.0.0/8", Condition{Operator: "IpAddress", Key: "aws:SourceIp", Values: []string{"10.0.0.0/8"}}},
		{"aws:SourceIp=nip:10.0.0.0/8", Condition{Operator: "NotIpAddress", Key: "aws:SourceIp", Values: []string{"10.0.0.0/8"}}},
	}
	for _, tc := range tests {
		t.Run(tc.dsl, func(t *testing.T) {
			got, err := ParseCondition(tc.dsl)
			if err != nil {
				t.Fatalf("ParseCondition(%q): %v", tc.dsl, err)
			}
			if !reflect.DeepEqual(*got, tc.want) {
				t.Errorf("ParseCondition(%q) = %+v, want %+v", tc.dsl, *got, tc.want)
			}
		})
	}
}

func TestParseCondition_Modifiers(t *testing.T) {
	tests := []struct {
		dsl  string
		want Condition
	}{
		{"jwt:groups=any-eq:eng,security", Condition{Operator: "ForAnyValue:StringEquals", Key: "jwt:groups", Values: []string{"eng", "security"}}},
		{"jwt:groups=all-eq:eng", Condition{Operator: "ForAllValues:StringEquals", Key: "jwt:groups", Values: []string{"eng"}}},
		{"jwt:groups=all-neq:guests", Condition{Operator: "ForAllValues:StringNotEquals", Key: "jwt:groups", Values: []string{"guests"}}},
		{"jwt:aud=eq?:purestorage", Condition{Operator: "StringEqualsIfExists", Key: "jwt:aud", Values: []string{"purestorage"}}},
		{"jwt:groups=any-eq?:eng", Condition{Operator: "ForAnyValue:StringEqualsIfExists", Key: "jwt:groups", Values: []string{"eng"}}},
		{"sts:DurationSeconds=lte?:3600", Condition{Operator: "NumericLessThanEqualsIfExists", Key: "sts:DurationSeconds", Values: []string{"3600"}}},
	}
	for _, tc := range tests {
		t.Run(tc.dsl, func(t *testing.T) {
			got, err := ParseCondition(tc.dsl)
			if err != nil {
				t.Fatalf("ParseCondition(%q): %v", tc.dsl, err)
			}
			if !reflect.DeepEqual(*got, tc.want) {
				t.Errorf("ParseCondition(%q) = %+v, want %+v", tc.dsl, *got, tc.want)
			}
		})
	}
}

func TestParseCondition_Errors(t *testing.T) {
	tests := []struct {
		dsl  string
		want string // substring in error
	}{
		{"missing-equals", "expected key=op:value"},
		{"jwt:aud=", "expected op:value"},
		{"jwt:aud=eq", "expected op:value"},
		{"jwt:aud=eq:", "empty value list"},
		{"jwt:aud=bogus:purestorage", "unknown operator shortcut"},
		{"ldap:foo=eq:bar", "unsupported condition key prefix"},
		{"=eq:purestorage", "empty key"},
	}
	for _, tc := range tests {
		t.Run(tc.dsl, func(t *testing.T) {
			_, err := ParseCondition(tc.dsl)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
