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
