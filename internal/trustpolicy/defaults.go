package trustpolicy

import (
	"fmt"
	"strings"
)

// recognizedClaims are the JWT claim names auto-included in mode A.
// "iss" is intentionally omitted — it informs the principal, not a condition.
var recognizedClaims = []string{"aud", "sub", "azp", "groups", "tid", "oid", "upn", "roles"}

// DefaultConditions returns the default set of conditions derived from a JWT's
// claims for mode A (targeted): only recognized claims contribute.
func DefaultConditions(claims map[string]interface{}) []Condition {
	return DefaultConditionsWithIncludes(claims, nil)
}

// DefaultConditionsWithIncludes is like DefaultConditions but also includes
// any extra claims listed in includes (each must be of the form "jwt:<name>").
func DefaultConditionsWithIncludes(claims map[string]interface{}, includes []string) []Condition {
	out := make([]Condition, 0)
	seen := make(map[string]bool)
	for _, name := range recognizedClaims {
		if cond := conditionFromClaim(name, claims[name]); cond != nil {
			out = append(out, *cond)
			seen[name] = true
		}
	}
	for _, inc := range includes {
		if !strings.HasPrefix(inc, "jwt:") {
			continue
		}
		name := strings.TrimPrefix(inc, "jwt:")
		if seen[name] {
			continue
		}
		if cond := conditionFromClaim(name, claims[name]); cond != nil {
			out = append(out, *cond)
		}
	}
	return out
}

// conditionFromClaim builds a default Condition for one claim, or returns nil
// if the claim is missing or has an unsupported shape.
func conditionFromClaim(name string, value interface{}) *Condition {
	if value == nil {
		return nil
	}
	key := "jwt:" + name
	switch v := value.(type) {
	case string:
		return &Condition{Operator: "StringEquals", Key: key, Values: []string{v}}
	case float64:
		return &Condition{Operator: "NumericEquals", Key: key, Values: []string{trimFloat(v)}}
	case bool:
		return &Condition{Operator: "StringEquals", Key: key, Values: []string{fmt.Sprintf("%t", v)}}
	case []interface{}:
		vals := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				vals = append(vals, s)
			}
		}
		if len(vals) == 0 {
			return nil
		}
		op := "ForAnyValue:StringEquals"
		if name == "aud" {
			// aud-as-array is a special case: AWS treats it as a list of allowed audiences,
			// which is naturally a StringEquals against any element.
			op = "StringEquals"
		}
		return &Condition{Operator: op, Key: key, Values: vals}
	}
	return nil
}

// trimFloat formats a float64 without unnecessary trailing zeros for whole numbers.
func trimFloat(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}
