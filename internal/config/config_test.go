package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestLoadFromTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".fbsts.toml")

	content := `
[okta]
tenant_url = "https://test.okta.com"
client_id = "test-client-id"
scopes = ["openid", "profile"]

[flashblade]
sts_endpoint = "https://fb-sts.example.com"
data_endpoint = "https://fb-data.example.com"
role_arn = "arn:aws:iam::123:role/test"
account = "testaccount"

[s3]
test_bucket = "my-bucket"
test_key_prefix = "test/"

[tls]
insecure = true
ca_cert = "/path/to/ca.pem"
`
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if cfg.OktaTenantURL != "https://test.okta.com" {
		t.Errorf("OktaTenantURL = %q, want %q", cfg.OktaTenantURL, "https://test.okta.com")
	}
	if cfg.OktaClientID != "test-client-id" {
		t.Errorf("OktaClientID = %q, want %q", cfg.OktaClientID, "test-client-id")
	}
	if len(cfg.OktaScopes) != 2 || cfg.OktaScopes[0] != "openid" {
		t.Errorf("OktaScopes = %v, want [openid profile]", cfg.OktaScopes)
	}
	if cfg.STSEndpoint != "https://fb-sts.example.com" {
		t.Errorf("STSEndpoint = %q", cfg.STSEndpoint)
	}
	if cfg.DataEndpoint != "https://fb-data.example.com" {
		t.Errorf("DataEndpoint = %q", cfg.DataEndpoint)
	}
	if cfg.RoleARN != "arn:aws:iam::123:role/test" {
		t.Errorf("RoleARN = %q", cfg.RoleARN)
	}
	if cfg.TestBucket != "my-bucket" {
		t.Errorf("TestBucket = %q", cfg.TestBucket)
	}
	if !cfg.Insecure {
		t.Error("Insecure should be true")
	}
	if cfg.CACert != "/path/to/ca.pem" {
		t.Errorf("CACert = %q", cfg.CACert)
	}
}

func TestLoadFromFileNotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/.fbsts.toml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestResolveConfigFileOrder(t *testing.T) {
	homeDir := t.TempDir()
	homeCfg := filepath.Join(homeDir, ".fbsts.toml")
	os.WriteFile(homeCfg, []byte(`
[okta]
tenant_url = "https://home.okta.com"
client_id = "home-client"
`), 0644)

	localDir := t.TempDir()
	localCfg := filepath.Join(localDir, ".fbsts.toml")
	os.WriteFile(localCfg, []byte(`
[okta]
tenant_url = "https://local.okta.com"
`), 0644)

	cfg, err := ResolveConfig(homeCfg, localCfg, "")
	if err != nil {
		t.Fatalf("ResolveConfig failed: %v", err)
	}

	if cfg.OktaTenantURL != "https://local.okta.com" {
		t.Errorf("OktaTenantURL = %q, want local override", cfg.OktaTenantURL)
	}
	if cfg.OktaClientID != "home-client" {
		t.Errorf("OktaClientID = %q, want home value", cfg.OktaClientID)
	}
}

func TestResolveConfigExplicitFile(t *testing.T) {
	dir := t.TempDir()
	explicit := filepath.Join(dir, "custom.toml")
	os.WriteFile(explicit, []byte(`
[okta]
tenant_url = "https://explicit.okta.com"
`), 0644)

	cfg, err := ResolveConfig("", "", explicit)
	if err != nil {
		t.Fatalf("ResolveConfig with explicit failed: %v", err)
	}

	if cfg.OktaTenantURL != "https://explicit.okta.com" {
		t.Errorf("OktaTenantURL = %q, want explicit value", cfg.OktaTenantURL)
	}
}

func TestApplyFlagOverrides(t *testing.T) {
	cfg := &TOMLConfig{}
	cfg.Okta.TenantURL = "https://original.okta.com"

	overrides := &FlagOverrides{
		OktaURL: "https://override.okta.com",
		Bucket:  "override-bucket",
	}

	ApplyOverrides(cfg, overrides)

	if cfg.Okta.TenantURL != "https://override.okta.com" {
		t.Errorf("OktaURL override failed: %q", cfg.Okta.TenantURL)
	}
	if cfg.S3.TestBucket != "override-bucket" {
		t.Errorf("Bucket override failed: %q", cfg.S3.TestBucket)
	}
}

func TestDefaultScopes(t *testing.T) {
	cfg := &TOMLConfig{}
	result := cfg.ToStepsConfig()
	if len(result.OktaScopes) != 3 {
		t.Errorf("default scopes should be [openid profile groups], got %v", result.OktaScopes)
	}
}

func TestDefaultDuration(t *testing.T) {
	cfg := &TOMLConfig{}
	result := cfg.ToStepsConfig()
	if result.Duration != 3600 {
		t.Errorf("default duration should be 3600, got %d", result.Duration)
	}
}

func TestLoadKeycloakConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".fbsts.toml")
	content := `
[keycloak]
issuer_url = "https://kc.example.com/realms/test"
client_id = "kc-client"
scopes = ["openid", "profile"]

[flashblade]
sts_endpoint = "https://fb-sts.example.com"
role_arn = "arn:aws:iam::123:role/test"
`
	os.WriteFile(path, []byte(content), 0644)
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}
	if cfg.KeycloakIssuerURL != "https://kc.example.com/realms/test" {
		t.Errorf("KeycloakIssuerURL = %q", cfg.KeycloakIssuerURL)
	}
	if cfg.KeycloakClientID != "kc-client" {
		t.Errorf("KeycloakClientID = %q", cfg.KeycloakClientID)
	}
}

func TestDetectIDPOktaOnly(t *testing.T) {
	cfg := &TOMLConfig{}
	cfg.Okta.TenantURL = "https://myorg.okta.com"
	cfg.Okta.ClientID = "client-id"
	detected, err := DetectIDP(cfg, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detected != "okta" {
		t.Errorf("detected = %q, want okta", detected)
	}
}

func TestDetectIDPKeycloakOnly(t *testing.T) {
	cfg := &TOMLConfig{}
	cfg.Keycloak.IssuerURL = "https://kc.example.com/realms/test"
	cfg.Keycloak.ClientID = "kc-client"
	detected, err := DetectIDP(cfg, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detected != "keycloak" {
		t.Errorf("detected = %q, want keycloak", detected)
	}
}

func TestDetectIDPBothConfiguredNoFlag(t *testing.T) {
	cfg := &TOMLConfig{}
	cfg.Okta.TenantURL = "https://myorg.okta.com"
	cfg.Okta.ClientID = "client-id"
	cfg.Keycloak.IssuerURL = "https://kc.example.com/realms/test"
	cfg.Keycloak.ClientID = "kc-client"
	_, err := DetectIDP(cfg, "")
	if err == nil {
		t.Fatal("expected error when both IDPs configured without --idp flag")
	}
}

func TestDetectIDPExplicitFlag(t *testing.T) {
	cfg := &TOMLConfig{}
	cfg.Okta.TenantURL = "https://myorg.okta.com"
	cfg.Okta.ClientID = "client-id"
	cfg.Keycloak.IssuerURL = "https://kc.example.com/realms/test"
	cfg.Keycloak.ClientID = "kc-client"
	detected, err := DetectIDP(cfg, "keycloak")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detected != "keycloak" {
		t.Errorf("detected = %q, want keycloak", detected)
	}
}

func TestDetectIDPFlagMissingSection(t *testing.T) {
	cfg := &TOMLConfig{}
	cfg.Okta.TenantURL = "https://myorg.okta.com"
	_, err := DetectIDP(cfg, "keycloak")
	if err == nil {
		t.Fatal("expected error when --idp keycloak but no [keycloak] section")
	}
}

func TestLoadFromTOML_OIDCProviders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".fbsts.toml")
	content := `
[okta]
tenant_url = "https://x.okta.com"
client_id = "abc"

[flashblade]
sts_endpoint = "https://fb"
data_endpoint = "https://fb-data"
role_arn = "prn::iam:array-id/local:obj-account-id/39:role/admin"
arn_format = "prn"

[oidc_providers]
"https://x.okta.com" = "okta-for-object"
"https://kc.example/realms/r" = "keycloak-r"
`
	os.WriteFile(path, []byte(content), 0644)

	tc, err := loadTOML(path)
	if err != nil {
		t.Fatalf("loadTOML: %v", err)
	}
	if tc.FlashBlade.ArnFormat != "prn" {
		t.Errorf("ArnFormat = %q, want prn", tc.FlashBlade.ArnFormat)
	}
	if tc.OIDCProviders["https://x.okta.com"] != "okta-for-object" {
		t.Errorf("OIDCProviders[okta] = %q", tc.OIDCProviders["https://x.okta.com"])
	}
	if tc.OIDCProviders["https://kc.example/realms/r"] != "keycloak-r" {
		t.Errorf("OIDCProviders[keycloak] = %q", tc.OIDCProviders["https://kc.example/realms/r"])
	}
}

func TestResolveConfig_OIDCProvidersMergedAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home.toml")
	local := filepath.Join(dir, "local.toml")

	os.WriteFile(home, []byte(`
[flashblade]
sts_endpoint = "https://fb"
data_endpoint = "https://fb-data"
role_arn = "prn::iam:x:role/r"
arn_format = "prn"

[oidc_providers]
"https://a" = "a-provider"
`), 0644)

	os.WriteFile(local, []byte(`
[oidc_providers]
"https://b" = "b-provider"
`), 0644)

	// Load each into a TOMLConfig manually (since ResolveConfig returns *steps.Config
	// which drops the new fields). Exercise MergeTOML directly.
	merged := &TOMLConfig{}
	for _, p := range []string{home, local} {
		tc, err := loadTOML(p)
		if err != nil {
			t.Fatalf("loadTOML(%q): %v", p, err)
		}
		MergeTOML(merged, tc)
	}

	if merged.FlashBlade.ArnFormat != "prn" {
		t.Errorf("ArnFormat = %q, want prn", merged.FlashBlade.ArnFormat)
	}
	if merged.OIDCProviders["https://a"] != "a-provider" {
		t.Errorf("OIDCProviders[a] = %q", merged.OIDCProviders["https://a"])
	}
	if merged.OIDCProviders["https://b"] != "b-provider" {
		t.Errorf("OIDCProviders[b] = %q", merged.OIDCProviders["https://b"])
	}
}

func TestSniffArnFormat(t *testing.T) {
	tests := map[string]string{
		"prn::iam:array-id/local:obj-account-id/39:role/admin": "prn",
		"arn:aws:iam::123:role/test":                           "aws",
		"":                                                     "aws", // default
		"unknown-format":                                       "aws", // default fallback
	}
	for in, want := range tests {
		if got := SniffArnFormat(in); got != want {
			t.Errorf("SniffArnFormat(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEntraIDConfigParsesAndMerges(t *testing.T) {
	tomlStr := `
[entraid]
issuer_url = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
client_id = "app-client-id"
scopes = ["openid", "profile", "api://app/.default"]
`
	var cfg TOMLConfig
	if _, err := toml.Decode(tomlStr, &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.EntraID.IssuerURL == "" {
		t.Error("expected EntraID.IssuerURL to parse, got empty")
	}
	if cfg.EntraID.ClientID != "app-client-id" {
		t.Errorf("expected client_id %q, got %q", "app-client-id", cfg.EntraID.ClientID)
	}
	if len(cfg.EntraID.Scopes) != 3 {
		t.Errorf("expected 3 scopes, got %d", len(cfg.EntraID.Scopes))
	}
}

func TestMergeTOMLEntraID(t *testing.T) {
	dst := &TOMLConfig{}
	src := &TOMLConfig{EntraID: EntraIDConfig{
		IssuerURL: "https://login.microsoftonline.com/tenant/v2.0",
		ClientID:  "cid",
		Scopes:    []string{"openid"},
	}}
	MergeTOML(dst, src)
	if dst.EntraID.IssuerURL != src.EntraID.IssuerURL {
		t.Errorf("merge did not copy IssuerURL")
	}
	if dst.EntraID.ClientID != "cid" {
		t.Errorf("merge did not copy ClientID")
	}
	if len(dst.EntraID.Scopes) != 1 {
		t.Errorf("merge did not copy Scopes")
	}
}
