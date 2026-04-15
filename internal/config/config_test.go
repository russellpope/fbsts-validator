package config

import (
	"os"
	"path/filepath"
	"testing"
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
