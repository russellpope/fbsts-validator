package trustpolicy

import (
	"encoding/json"
	"strings"
)

// ruleBodyJSON mirrors the FlashBlade rule-add REST body shape.
type ruleBodyJSON struct {
	Name       string              `json:"name"`
	Effect     string              `json:"effect"`
	Principal  principalBodyJSON   `json:"principal"`
	Action     string              `json:"action"`
	Conditions []conditionBodyJSON `json:"conditions"`
}

type principalBodyJSON struct {
	Federated string `json:"federated"`
}

type conditionBodyJSON struct {
	Operator string   `json:"operator"`
	Key      string   `json:"key"`
	Values   []string `json:"values"`
}

// EncodeRuleBody serializes a Rule into the FlashBlade rule-add body JSON shape.
// Output is indented for readability (2-space).
func EncodeRuleBody(r *Rule) ([]byte, error) {
	conds := make([]conditionBodyJSON, len(r.Conditions))
	for i, c := range r.Conditions {
		conds[i] = conditionBodyJSON{Operator: c.Operator, Key: c.Key, Values: c.Values}
	}
	body := ruleBodyJSON{
		Name:       r.Name,
		Effect:     r.Effect,
		Principal:  principalBodyJSON{Federated: r.Principal.Federated},
		Action:     r.Action,
		Conditions: conds,
	}
	return json.MarshalIndent(body, "", "  ")
}

// EncodeIAMDocument serializes one or more Rules into an AWS IAM policy document.
// Output is indented for readability (2-space).
func EncodeIAMDocument(rules []Rule) ([]byte, error) {
	stmts := make([]map[string]interface{}, len(rules))
	for i, r := range rules {
		stmts[i] = map[string]interface{}{
			"Sid":       sanitizeSid(r.Name),
			"Effect":    titleCaseEffect(r.Effect),
			"Principal": map[string]interface{}{"Federated": r.Principal.Federated},
			"Action":    r.Action,
			"Condition": iamConditionBlock(r.Conditions),
		}
	}
	doc := map[string]interface{}{
		"Version":   "2012-10-17",
		"Statement": stmts,
	}
	return json.MarshalIndent(doc, "", "  ")
}

// iamConditionBlock groups conditions by operator, mapping each key to either
// a scalar (single value) or a list (multi value).
func iamConditionBlock(conds []Condition) map[string]map[string]interface{} {
	out := make(map[string]map[string]interface{})
	for _, c := range conds {
		bucket, ok := out[c.Operator]
		if !ok {
			bucket = make(map[string]interface{})
			out[c.Operator] = bucket
		}
		if len(c.Values) == 1 {
			bucket[c.Key] = c.Values[0]
		} else {
			vals := make([]interface{}, len(c.Values))
			for i, v := range c.Values {
				vals[i] = v
			}
			bucket[c.Key] = vals
		}
	}
	return out
}

// sanitizeSid strips any non-alphanumeric characters per AWS IAM Sid rules.
func sanitizeSid(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// titleCaseEffect converts "allow"/"deny" to AWS IAM's "Allow"/"Deny" form.
func titleCaseEffect(e string) string {
	switch strings.ToLower(e) {
	case "allow":
		return "Allow"
	case "deny":
		return "Deny"
	default:
		return e
	}
}
