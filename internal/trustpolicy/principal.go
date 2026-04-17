package trustpolicy

import (
	"fmt"
	"strings"
)

// PrincipalResolver resolves an OIDC provider name into a Federated principal
// ARN/PRN, given configured providers, an explicit flag, and the role-ARN context.
type PrincipalResolver struct {
	// FlagARN, if non-empty, is used verbatim (highest priority).
	FlagARN string
	// FlagName, if non-empty, is formatted into an ARN/PRN.
	FlagName string
	// ProvidersByISS maps JWT issuer URL → FB-side OIDC provider name.
	ProvidersByISS map[string]string
	// ARNFormat is "prn" or "aws"; controls how a name is formatted into a full ARN.
	ARNFormat string
	// RoleARN provides PRN context (array-id, account-id) when ARNFormat is "prn".
	RoleARN string
}

// Resolve returns the federated principal ARN. Resolution priority:
// 1. FlagARN (verbatim)
// 2. FlagName (formatted)
// 3. ProvidersByISS lookup on iss (formatted)
// 4. error
func (r *PrincipalResolver) Resolve(iss string) (string, error) {
	if r.FlagARN != "" {
		return r.FlagARN, nil
	}
	if r.FlagName != "" {
		return r.format(r.FlagName), nil
	}
	if iss != "" {
		if name, ok := r.ProvidersByISS[iss]; ok {
			return r.format(name), nil
		}
	}
	if iss == "" {
		return "", fmt.Errorf("cannot resolve OIDC principal: --principal or --principal-arn is required when no JWT is supplied")
	}
	return "", fmt.Errorf("cannot resolve OIDC principal: JWT iss %q not in [oidc_providers] config and --principal not set", iss)
}

// format builds a full ARN/PRN from a provider name.
func (r *PrincipalResolver) format(name string) string {
	switch r.ARNFormat {
	case "prn":
		return prnPrincipal(r.RoleARN, name)
	default:
		return "arn:aws:iam:::oidc-provider/" + name
	}
}

// prnPrincipal swaps the ":role/<x>" tail of a role PRN with ":oidc-provider/<name>".
// Falls back to a synthesized PRN if RoleARN is missing or unparseable.
func prnPrincipal(roleARN, name string) string {
	idx := strings.Index(roleARN, ":role/")
	if idx < 0 {
		// Fall back: best-effort PRN with no array context.
		return "prn::iam:::oidc-provider/" + name
	}
	return roleARN[:idx] + ":oidc-provider/" + name
}
