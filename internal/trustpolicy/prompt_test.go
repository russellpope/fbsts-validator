package trustpolicy

import (
	"bufio"
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// drive runs the prompter with canned input and captures output.
func drive(t *testing.T, claims []ClassifiedClaim, input string) ([]Condition, string) {
	t.Helper()
	in := bufio.NewReader(strings.NewReader(input))
	var out bytes.Buffer
	conds, err := WalkClaims(claims, in, &out)
	if err != nil {
		t.Fatalf("WalkClaims: %v", err)
	}
	return conds, out.String()
}

func TestWalkClaims_AcceptDefaults(t *testing.T) {
	claims := []ClassifiedClaim{
		{Name: "aud", Value: "purestorage", Kind: SingleString},
		{Name: "sub", Value: "user1", Kind: SingleString},
	}
	// Three blank lines → accept include default (Y) for both, accept default operator for both.
	got, _ := drive(t, claims, "\n\n\n\n")

	want := []Condition{
		{Operator: "StringEquals", Key: "jwt:aud", Values: []string{"purestorage"}},
		{Operator: "StringEquals", Key: "jwt:sub", Values: []string{"user1"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestWalkClaims_DeclineCustom(t *testing.T) {
	claims := []ClassifiedClaim{
		{Name: "custom", Value: "x", Kind: SingleString},
	}
	// Default for unrecognized claim is N → blank line means N → no condition.
	got, _ := drive(t, claims, "\n")
	if len(got) != 0 {
		t.Errorf("expected no conditions, got %+v", got)
	}
}

func TestWalkClaims_MultiValueAny(t *testing.T) {
	claims := []ClassifiedClaim{
		{Name: "groups", Value: []interface{}{"eng", "security"}, Kind: MultiString},
	}
	// Y to include, blank for ForAnyValue default, blank for StringEquals default, blank for keep values.
	got, _ := drive(t, claims, "Y\n\n\n\n")
	if len(got) != 1 {
		t.Fatalf("got %d conditions, want 1", len(got))
	}
	if got[0].Operator != "ForAnyValue:StringEquals" {
		t.Errorf("operator = %q, want ForAnyValue:StringEquals", got[0].Operator)
	}
	if !reflect.DeepEqual(got[0].Values, []string{"eng", "security"}) {
		t.Errorf("values = %v", got[0].Values)
	}
}

func TestWalkClaims_MultiValueAll(t *testing.T) {
	claims := []ClassifiedClaim{
		{Name: "groups", Value: []interface{}{"eng"}, Kind: MultiString},
	}
	// Y include, "2" for ForAllValues, blank operator default, blank keep values.
	got, _ := drive(t, claims, "Y\n2\n\n\n")
	if got[0].Operator != "ForAllValues:StringEquals" {
		t.Errorf("operator = %q, want ForAllValues:StringEquals", got[0].Operator)
	}
}

func TestWalkClaims_OverrideValues(t *testing.T) {
	claims := []ClassifiedClaim{
		{Name: "aud", Value: "purestorage", Kind: SingleString},
	}
	// Y include, blank operator default, type new value.
	got, _ := drive(t, claims, "Y\n\nfoobar\n")
	if got[0].Values[0] != "foobar" {
		t.Errorf("override failed: %v", got[0].Values)
	}
}
