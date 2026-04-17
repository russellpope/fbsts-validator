package trustpolicy

import (
	"strings"
	"testing"
)

func TestResolvePrincipal_FlagARN(t *testing.T) {
	r := PrincipalResolver{
		FlagARN:        "arn:aws:iam:::oidc-provider/myidp",
		FlagName:       "ignored",
		ProvidersByISS: map[string]string{"https://idp.example": "alsoignored"},
		ARNFormat:      "aws",
	}
	got, err := r.Resolve("https://idp.example")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "arn:aws:iam:::oidc-provider/myidp" {
		t.Errorf("got %q, want flag value verbatim", got)
	}
}

func TestResolvePrincipal_FlagName_AWS(t *testing.T) {
	r := PrincipalResolver{
		FlagName:  "okta-for-object",
		ARNFormat: "aws",
	}
	got, err := r.Resolve("https://idp.example")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "arn:aws:iam:::oidc-provider/okta-for-object" {
		t.Errorf("got %q", got)
	}
}

func TestResolvePrincipal_FlagName_PRN(t *testing.T) {
	r := PrincipalResolver{
		FlagName:  "okta-for-object",
		ARNFormat: "prn",
		RoleARN:   "prn::iam:array-id/local:obj-account-id/39:role/admin",
	}
	got, err := r.Resolve("https://idp.example")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := "prn::iam:array-id/local:obj-account-id/39:oidc-provider/okta-for-object"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestResolvePrincipal_ConfigByISS(t *testing.T) {
	r := PrincipalResolver{
		ProvidersByISS: map[string]string{
			"https://idp.example": "okta-for-object",
		},
		ARNFormat: "aws",
	}
	got, err := r.Resolve("https://idp.example")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "arn:aws:iam:::oidc-provider/okta-for-object" {
		t.Errorf("got %q", got)
	}
}

func TestResolvePrincipal_NoMatch(t *testing.T) {
	r := PrincipalResolver{
		ProvidersByISS: map[string]string{"https://other.example": "x"},
		ARNFormat:      "aws",
	}
	_, err := r.Resolve("https://idp.example")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "https://idp.example") {
		t.Errorf("error %q does not mention iss", err.Error())
	}
	if !strings.Contains(err.Error(), "--principal") {
		t.Errorf("error %q does not mention --principal", err.Error())
	}
}

func TestResolvePrincipal_NoJWT_NoFlag(t *testing.T) {
	r := PrincipalResolver{ARNFormat: "aws"}
	_, err := r.Resolve("")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
