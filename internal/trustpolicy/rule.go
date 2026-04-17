package trustpolicy

import (
	"fmt"
)

// Principal holds the federated identity provider reference.
type Principal struct {
	Federated string
}

// Rule is the in-memory representation of a single trust policy rule.
type Rule struct {
	Name       string
	Effect     string // "allow" | "deny"
	Principal  Principal
	Action     string
	Conditions []Condition
}

// NewRule returns a Rule with sensible defaults: effect=allow, action=sts:AssumeRoleWithWebIdentity.
func NewRule() *Rule {
	return &Rule{
		Effect: "allow",
		Action: "sts:AssumeRoleWithWebIdentity",
	}
}

// AutoRuleName returns a deterministic rule name of the form "rule-<short-sub>-<unix>".
// Falls back to "rule-<unix>" if sub is empty. The sub fragment is derived by
// splitting the sub on non-alphanumeric delimiters, capping each segment at 8
// chars, and joining successive segments until the total length reaches 8
// (or the sub is exhausted).
func AutoRuleName(sub string, unixSeconds int64) string {
	short := shortenSub(sub)
	if short == "" {
		return fmt.Sprintf("rule-%d", unixSeconds)
	}
	return fmt.Sprintf("rule-%s-%d", short, unixSeconds)
}

func shortenSub(sub string) string {
	out := make([]byte, 0, 8)
	segLen := 0
	for i := 0; i < len(sub); i++ {
		c := sub[i]
		if isAlnum(c) {
			if segLen < 8 {
				out = append(out, c)
				segLen++
			}
			continue
		}
		// Non-alphanumeric ends the current segment.
		if len(out) >= 8 {
			break
		}
		segLen = 0
	}
	return string(out)
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}
