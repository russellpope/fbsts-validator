package trustpolicy

import (
	"fmt"
	"strings"
)

// Condition represents a single trust policy rule condition (operator + key + values).
type Condition struct {
	Operator string
	Key      string
	Values   []string
}

// SupportedKeyPrefixes lists the condition key prefixes FlashBlade accepts.
var SupportedKeyPrefixes = []string{"jwt:", "saml:", "aws:", "sts:"}

// shortcutOperators maps DSL shortcuts to AWS IAM operator names.
var shortcutOperators = map[string]string{
	"eq":      "StringEquals",
	"neq":     "StringNotEquals",
	"like":    "StringLike",
	"nlike":   "StringNotLike",
	"num-eq":  "NumericEquals",
	"num-neq": "NumericNotEquals",
	"lt":      "NumericLessThan",
	"lte":     "NumericLessThanEquals",
	"gt":      "NumericGreaterThan",
	"gte":     "NumericGreaterThanEquals",
	"ip":      "IpAddress",
	"nip":     "NotIpAddress",
}

// ParseCondition parses a DSL string of the form "key=op:value[,value...]"
// into a Condition. Operator shortcuts and modifiers are documented in the spec.
func ParseCondition(dsl string) (*Condition, error) {
	eq := strings.IndexByte(dsl, '=')
	if eq < 0 {
		return nil, fmt.Errorf("condition %q: expected key=op:value", dsl)
	}
	key := dsl[:eq]
	rest := dsl[eq+1:]

	if key == "" {
		return nil, fmt.Errorf("condition %q: empty key", dsl)
	}
	if !hasSupportedPrefix(key) {
		return nil, fmt.Errorf("condition %q: unsupported condition key prefix %q — supported: %s",
			dsl, prefixOf(key), strings.Join(SupportedKeyPrefixes, ", "))
	}

	colon := strings.IndexByte(rest, ':')
	if colon < 0 || colon == len(rest)-1 {
		// no colon at all, OR colon at the end with empty value
		if colon < 0 {
			return nil, fmt.Errorf("condition %q: expected op:value after =", dsl)
		}
		return nil, fmt.Errorf("condition %q: empty value list", dsl)
	}
	rawOp := rest[:colon]
	rawValues := rest[colon+1:]

	op, err := expandOperator(rawOp)
	if err != nil {
		return nil, fmt.Errorf("condition %q: %w", dsl, err)
	}

	values := strings.Split(rawValues, ",")
	for i := range values {
		values[i] = strings.TrimSpace(values[i])
	}
	if len(values) == 1 && values[0] == "" {
		return nil, fmt.Errorf("condition %q: empty value list", dsl)
	}

	return &Condition{Operator: op, Key: key, Values: values}, nil
}

// expandOperator turns a DSL shortcut into the canonical AWS IAM operator.
// Supports prefixes "any-" → "ForAnyValue:" and "all-" → "ForAllValues:".
// Supports suffix "?" → "IfExists" variant.
func expandOperator(raw string) (string, error) {
	qualifier := ""
	if strings.HasPrefix(raw, "any-") {
		qualifier = "ForAnyValue:"
		raw = raw[len("any-"):]
	} else if strings.HasPrefix(raw, "all-") {
		qualifier = "ForAllValues:"
		raw = raw[len("all-"):]
	}

	ifExists := false
	if strings.HasSuffix(raw, "?") {
		ifExists = true
		raw = raw[:len(raw)-1]
	}

	canonical, ok := shortcutOperators[raw]
	if !ok {
		return "", fmt.Errorf("unknown operator shortcut %q (valid: eq, neq, like, nlike, num-eq, num-neq, lt, lte, gt, gte, ip, nip; with optional any-/all- prefix and ? suffix)", raw)
	}
	if ifExists {
		canonical += "IfExists"
	}
	return qualifier + canonical, nil
}

func hasSupportedPrefix(key string) bool {
	for _, p := range SupportedKeyPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

func prefixOf(key string) string {
	if i := strings.IndexByte(key, ':'); i >= 0 {
		return key[:i+1]
	}
	return key
}
