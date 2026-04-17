package trustpolicy

import (
	"bufio"
	"fmt"
	"io"
	"time"
)

// Inputs aggregates everything the trust-policy entry points need to build a Rule.
// Fields not used by a given entry point may be left zero.
type Inputs struct {
	// Token is a raw JWT string. Required for FromJWT and Interactive; ignored by Build.
	Token string

	// Conditions are extra conditions added on top of any derived from the JWT.
	// Used by all three entry points.
	Conditions []Condition

	// IncludeClaims is a list of "jwt:<name>" identifiers to include from the JWT
	// even when not in the recognizedClaims set. FromJWT only.
	IncludeClaims []string

	// Resolver computes the federated principal ARN.
	Resolver *PrincipalResolver

	// Effect is "allow" or "deny". Empty means "allow".
	Effect string

	// RuleName overrides the auto-generated name. Empty means auto.
	RuleName string

	// Now provides the timestamp for auto-generated rule names. nil means time.Now.
	Now func() time.Time

	// Reader and Writer are used by Interactive for prompts. nil means stdio.
	Reader *bufio.Reader
	Writer io.Writer
}

// FromJWT decodes the JWT, derives default conditions from recognized claims,
// merges in any extra conditions from Inputs, resolves the principal, and
// returns the assembled Rule.
func FromJWT(in Inputs) (*Rule, error) {
	dec, err := DecodeJWT(in.Token)
	if err != nil {
		return nil, err
	}
	defaults := DefaultConditionsWithIncludes(dec.Claims, in.IncludeClaims)
	conds := mergeConditions(defaults, in.Conditions)
	return assemble(dec.Claims, conds, in)
}

// Interactive decodes the JWT, walks each claim with sequential prompts,
// merges any extra --condition flags, resolves the principal, and returns
// the assembled Rule.
func Interactive(in Inputs) (*Rule, error) {
	dec, err := DecodeJWT(in.Token)
	if err != nil {
		return nil, err
	}
	classified := ClassifyClaims(dec.Claims)
	walked, err := WalkClaims(classified, in.Reader, in.Writer)
	if err != nil {
		return nil, err
	}
	conds := mergeConditions(walked, in.Conditions)
	return assemble(dec.Claims, conds, in)
}

// mergeConditions combines default-derived conditions with user-supplied ones.
// User conditions REPLACE any default-derived condition that targets the same Key
// (regardless of operator). This avoids emitting two condition entries for the
// same key — under AWS IAM AND-across-same-key semantics that would produce
// surprising over-restriction.
func mergeConditions(defaults, overrides []Condition) []Condition {
	overriddenKeys := make(map[string]bool, len(overrides))
	for _, c := range overrides {
		overriddenKeys[c.Key] = true
	}
	out := make([]Condition, 0, len(defaults)+len(overrides))
	for _, c := range defaults {
		if !overriddenKeys[c.Key] {
			out = append(out, c)
		}
	}
	out = append(out, overrides...)
	return out
}

// Build assembles a Rule from --condition flags only — no JWT.
func Build(in Inputs) (*Rule, error) {
	if len(in.Conditions) == 0 {
		return nil, fmt.Errorf("Build: at least one --condition is required when no JWT is supplied")
	}
	return assemble(nil, in.Conditions, in)
}

// assemble is the shared finalization step: principal resolution, name auto-gen,
// effect handling, timestamp.
func assemble(claims map[string]interface{}, conds []Condition, in Inputs) (*Rule, error) {
	iss, _ := claims["iss"].(string)
	federated, err := in.Resolver.Resolve(iss)
	if err != nil {
		return nil, err
	}

	rule := NewRule()
	rule.Principal.Federated = federated
	rule.Conditions = conds
	if in.Effect != "" {
		rule.Effect = in.Effect
	}
	if in.RuleName != "" {
		rule.Name = in.RuleName
	} else {
		now := in.Now
		if now == nil {
			now = time.Now
		}
		sub, _ := claims["sub"].(string)
		rule.Name = AutoRuleName(sub, now().Unix())
	}
	return rule, nil
}
