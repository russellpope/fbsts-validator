package trustpolicy

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// WalkClaims walks each classified claim and prompts the user to include it
// as a condition. Output goes to w; input is read from in.
func WalkClaims(claims []ClassifiedClaim, in *bufio.Reader, w io.Writer) ([]Condition, error) {
	var out []Condition
	for _, c := range claims {
		cond, err := promptClaim(c, in, w)
		if err != nil {
			return nil, err
		}
		if cond != nil {
			out = append(out, *cond)
		}
	}
	return out, nil
}

// promptClaim runs the include / operator / value-override sequence for one claim.
func promptClaim(c ClassifiedClaim, in *bufio.Reader, w io.Writer) (*Condition, error) {
	defaultY := isRecognized(c.Name)
	def := "n"
	if defaultY {
		def = "y"
	}
	answer, err := prompt(in, w, fmt.Sprintf("Include %q (= %v)? [Y/n]", "jwt:"+c.Name, c.Value), def)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(answer, "y") {
		return nil, nil
	}

	qualifier := ""
	if c.Kind == MultiString {
		choice, err := prompt(in, w, "  Value-set semantics: [1] ForAnyValue (default)  [2] ForAllValues", "1")
		if err != nil {
			return nil, err
		}
		if choice == "2" {
			qualifier = "ForAllValues:"
		} else {
			qualifier = "ForAnyValue:"
		}
	}

	defaultOp := defaultOperatorFor(c.Name, c.Kind)
	op, err := prompt(in, w, fmt.Sprintf("  Operator (default %s)", defaultOp), defaultOp)
	if err != nil {
		return nil, err
	}

	values := claimValuesAsStrings(c.Value)
	override, err := prompt(in, w, fmt.Sprintf("  Values (default %s)", strings.Join(values, ",")), strings.Join(values, ","))
	if err != nil {
		return nil, err
	}
	values = splitTrim(override)

	return &Condition{Operator: qualifier + op, Key: "jwt:" + c.Name, Values: values}, nil
}

// prompt prints a question, reads a line, and returns the trimmed answer or
// the supplied default if the user pressed Enter.
func prompt(in *bufio.Reader, w io.Writer, q, def string) (string, error) {
	fmt.Fprintf(w, "%s: ", q)
	line, err := in.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return def, nil
	}
	return line, nil
}

func isRecognized(name string) bool {
	for _, n := range recognizedClaims {
		if n == name {
			return true
		}
	}
	return false
}

func defaultOperatorFor(name string, kind Kind) string {
	switch kind {
	case SingleNumber:
		return "NumericEquals"
	default:
		return "StringEquals"
	}
}

func claimValuesAsStrings(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case bool:
		return []string{fmt.Sprintf("%t", val)}
	case float64:
		return []string{trimFloat(val)}
	case []interface{}:
		out := make([]string, 0, len(val))
		for _, e := range val {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func splitTrim(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
