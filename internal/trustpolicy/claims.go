package trustpolicy

import (
	"sort"
)

// Kind classifies a JWT claim by value shape, used to pick default operators
// and shape interactive prompts.
type Kind int

const (
	Other Kind = iota
	SingleString
	SingleNumber
	SingleBool
	MultiString
)

// ClassifiedClaim holds a claim's name, raw value, and inferred Kind.
type ClassifiedClaim struct {
	Name  string
	Value interface{}
	Kind  Kind
}

// ClassifyClaims walks a parsed JWT claims map and returns claims in stable
// alphabetical order with their inferred Kind.
func ClassifyClaims(claims map[string]interface{}) []ClassifiedClaim {
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]ClassifiedClaim, 0, len(keys))
	for _, k := range keys {
		out = append(out, ClassifiedClaim{Name: k, Value: claims[k], Kind: classify(claims[k])})
	}
	return out
}

func classify(v interface{}) Kind {
	switch val := v.(type) {
	case string:
		return SingleString
	case float64:
		return SingleNumber
	case bool:
		return SingleBool
	case []interface{}:
		// Multi-string only if every element is a string. Otherwise Other.
		for _, e := range val {
			if _, ok := e.(string); !ok {
				return Other
			}
		}
		return MultiString
	default:
		return Other
	}
}
