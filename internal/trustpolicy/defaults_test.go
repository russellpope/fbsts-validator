package trustpolicy

import (
	"reflect"
	"sort"
	"testing"
)

func TestDefaultConditionsFromClaims(t *testing.T) {
	claims := map[string]interface{}{
		"iss":    "https://idp.example",
		"sub":    "user1",
		"aud":    "purestorage",
		"azp":    "client-1",
		"groups": []interface{}{"eng", "security"},
		"custom": "ignored",
		"exp":    float64(1713300000),
	}
	got := DefaultConditions(claims)

	want := []Condition{
		{Operator: "StringEquals", Key: "jwt:aud", Values: []string{"purestorage"}},
		{Operator: "StringEquals", Key: "jwt:azp", Values: []string{"client-1"}},
		{Operator: "ForAnyValue:StringEquals", Key: "jwt:groups", Values: []string{"eng", "security"}},
		{Operator: "StringEquals", Key: "jwt:sub", Values: []string{"user1"}},
	}
	sortConds := func(cs []Condition) { sort.Slice(cs, func(i, j int) bool { return cs[i].Key < cs[j].Key }) }
	sortConds(got)
	sortConds(want)

	if !reflect.DeepEqual(got, want) {
		t.Errorf("DefaultConditions =\n  %+v\nwant\n  %+v", got, want)
	}
}

func TestDefaultConditions_AudArray(t *testing.T) {
	// aud may legitimately be an array per the JWT spec.
	claims := map[string]interface{}{
		"aud": []interface{}{"purestorage", "other"},
	}
	got := DefaultConditions(claims)
	if len(got) != 1 {
		t.Fatalf("got %d conditions, want 1", len(got))
	}
	if got[0].Key != "jwt:aud" || got[0].Operator != "StringEquals" {
		t.Errorf("aud condition = %+v", got[0])
	}
	if len(got[0].Values) != 2 || got[0].Values[0] != "purestorage" || got[0].Values[1] != "other" {
		t.Errorf("aud values = %+v", got[0].Values)
	}
}

func TestDefaultConditions_IncludeClaim(t *testing.T) {
	claims := map[string]interface{}{
		"sub":    "user1",
		"custom": "extra",
	}
	got := DefaultConditionsWithIncludes(claims, []string{"jwt:custom"})

	hasCustom := false
	for _, c := range got {
		if c.Key == "jwt:custom" {
			hasCustom = true
			if c.Operator != "StringEquals" || c.Values[0] != "extra" {
				t.Errorf("custom condition = %+v", c)
			}
		}
	}
	if !hasCustom {
		t.Errorf("--include-claim jwt:custom not honored: %+v", got)
	}
}

func TestDefaultConditionsEntraIDClaims(t *testing.T) {
	// Entra-shaped JWT claims fixture. Values fabricated from Entra v2.0 token docs.
	claims := map[string]interface{}{
		"iss":                "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
		"aud":                "api://app-client-id",
		"sub":                "aaaabbbb-0000-1111-2222-ccccddddeeee",
		"tid":                "11111111-1111-1111-1111-111111111111",
		"oid":                "00000000-0000-0000-0000-999999999999",
		"upn":                "alice@contoso.com",
		"preferred_username": "alice@contoso.com",
		"groups":             []interface{}{"Finance-Admins", "FlashBlade-Operators"},
		"roles":              []interface{}{"ObjectAdmin"},
		"scp":                "user_impersonation",
		"wids":               []interface{}{"12345678-aaaa-bbbb-cccc-123456789012"},
		"azp":                "app-client-id",
	}

	got := DefaultConditions(claims)

	byKey := map[string]Condition{}
	for _, c := range got {
		byKey[c.Key] = c
	}

	// Recognized Entra claims produce conditions.
	expectEntraCond(t, byKey, "jwt:tid", "StringEquals", []string{"11111111-1111-1111-1111-111111111111"})
	expectEntraCond(t, byKey, "jwt:oid", "StringEquals", []string{"00000000-0000-0000-0000-999999999999"})
	expectEntraCond(t, byKey, "jwt:upn", "StringEquals", []string{"alice@contoso.com"})
	expectEntraCond(t, byKey, "jwt:roles", "ForAnyValue:StringEquals", []string{"ObjectAdmin"})

	// Not-recognized Entra claims produce no conditions.
	for _, k := range []string{"jwt:preferred_username", "jwt:scp", "jwt:wids"} {
		if _, ok := byKey[k]; ok {
			t.Errorf("%s should not produce a default condition", k)
		}
	}

	// Pre-existing recognized claims still work for Entra's shapes.
	expectEntraCond(t, byKey, "jwt:aud", "StringEquals", []string{"api://app-client-id"})
	expectEntraCond(t, byKey, "jwt:sub", "StringEquals", []string{"aaaabbbb-0000-1111-2222-ccccddddeeee"})
	expectEntraCond(t, byKey, "jwt:azp", "StringEquals", []string{"app-client-id"})
	expectEntraCond(t, byKey, "jwt:groups", "ForAnyValue:StringEquals", []string{"Finance-Admins", "FlashBlade-Operators"})
}

// expectEntraCond asserts that byKey[key] exists with the expected operator and values.
func expectEntraCond(t *testing.T, byKey map[string]Condition, key, op string, values []string) {
	t.Helper()
	c, ok := byKey[key]
	if !ok {
		t.Errorf("missing condition for %s", key)
		return
	}
	if c.Operator != op {
		t.Errorf("%s: expected operator %q, got %q", key, op, c.Operator)
	}
	if len(c.Values) != len(values) {
		t.Errorf("%s: expected %d values, got %d (%v)", key, len(values), len(c.Values), c.Values)
		return
	}
	for i, v := range values {
		if c.Values[i] != v {
			t.Errorf("%s: values[%d] expected %q, got %q", key, i, v, c.Values[i])
		}
	}
}
