package trustpolicy

import (
	"strings"
	"testing"
)

func TestNewRule_Defaults(t *testing.T) {
	r := NewRule()
	if r.Effect != "allow" {
		t.Errorf("default Effect = %q, want allow", r.Effect)
	}
	if r.Action != "sts:AssumeRoleWithWebIdentity" {
		t.Errorf("default Action = %q, want sts:AssumeRoleWithWebIdentity", r.Action)
	}
}

func TestAutoRuleName_WithSub(t *testing.T) {
	got := AutoRuleName("user-12345-abcde", 1713300000)
	want := "rule-user12345-1713300000"
	if got != want {
		t.Errorf("AutoRuleName = %q, want %q", got, want)
	}
}

func TestAutoRuleName_WithoutSub(t *testing.T) {
	got := AutoRuleName("", 1713300000)
	want := "rule-1713300000"
	if got != want {
		t.Errorf("AutoRuleName = %q, want %q", got, want)
	}
}

func TestAutoRuleName_LongSub(t *testing.T) {
	got := AutoRuleName("00uxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 1713300000)
	if !strings.HasPrefix(got, "rule-00uxxxxx-") {
		t.Errorf("AutoRuleName = %q, want prefix rule-00uxxxxx-", got)
	}
	if !strings.HasSuffix(got, "-1713300000") {
		t.Errorf("AutoRuleName = %q, want suffix -1713300000", got)
	}
}

func TestAutoRuleName_SanitizesSub(t *testing.T) {
	// "@" and "." are not alphanumeric and must be stripped from the sub fragment.
	got := AutoRuleName("user@example.com", 1713300000)
	if strings.ContainsAny(got, "@.") {
		t.Errorf("AutoRuleName %q contains non-alphanumeric chars in sub fragment", got)
	}
}
