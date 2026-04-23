package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

// OktaConfig holds Okta-related TOML settings.
type OktaConfig struct {
	TenantURL string   `toml:"tenant_url"`
	ClientID  string   `toml:"client_id"`
	Scopes    []string `toml:"scopes"`
}

// KeycloakConfig holds Keycloak-related TOML settings.
type KeycloakConfig struct {
	IssuerURL string   `toml:"issuer_url"`
	ClientID  string   `toml:"client_id"`
	Scopes    []string `toml:"scopes"`
}

// EntraIDConfig holds Microsoft Entra ID TOML settings.
type EntraIDConfig struct {
	IssuerURL string   `toml:"issuer_url"`
	ClientID  string   `toml:"client_id"`
	Scopes    []string `toml:"scopes"`
}

// FlashBladeConfig holds FlashBlade STS/data endpoint TOML settings.
type FlashBladeConfig struct {
	STSEndpoint  string `toml:"sts_endpoint"`
	DataEndpoint string `toml:"data_endpoint"`
	RoleARN      string `toml:"role_arn"`
	Account      string `toml:"account"`
	Duration     int    `toml:"duration"`
	ArnFormat    string `toml:"arn_format"` // "prn" | "aws"; auto-sniffed if empty
}

// S3Config holds S3 test settings from TOML.
type S3Config struct {
	TestBucket    string `toml:"test_bucket"`
	TestKeyPrefix string `toml:"test_key_prefix"`
}

// TLSConfig holds TLS settings from TOML.
type TLSConfig struct {
	Insecure bool   `toml:"insecure"`
	CACert   string `toml:"ca_cert"`
}

// TOMLConfig mirrors the structure of the .fbsts.toml configuration file.
type TOMLConfig struct {
	Okta          OktaConfig        `toml:"okta"`
	Keycloak      KeycloakConfig    `toml:"keycloak"`
	EntraID       EntraIDConfig     `toml:"entraid"`
	FlashBlade    FlashBladeConfig  `toml:"flashblade"`
	S3            S3Config          `toml:"s3"`
	TLS           TLSConfig         `toml:"tls"`
	OIDCProviders map[string]string `toml:"oidc_providers"`

	// Behavior (set programmatically, not from TOML)
	ContinueOnError  bool
	PreSuppliedToken string
}

// FlagOverrides holds values supplied via CLI flags. An empty string means
// the flag was not set and should not override the config file value.
type FlagOverrides struct {
	OktaURL      string
	OktaClientID string
	STSEndpoint  string
	DataEndpoint string
	RoleARN      string
	Account      string
	Bucket       string
	KeyPrefix    string
	Insecure     bool
	CACert       string
	Duration     int
	Token        string
}

// loadTOML reads and parses a single TOML file into a TOMLConfig.
func loadTOML(path string) (*TOMLConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close()

	var cfg TOMLConfig
	if _, err := toml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	return &cfg, nil
}

// MergeTOML merges src into dst, overwriting only non-zero values from src.
func MergeTOML(dst, src *TOMLConfig) {
	if src.Okta.TenantURL != "" {
		dst.Okta.TenantURL = src.Okta.TenantURL
	}
	if src.Okta.ClientID != "" {
		dst.Okta.ClientID = src.Okta.ClientID
	}
	if len(src.Okta.Scopes) > 0 {
		dst.Okta.Scopes = src.Okta.Scopes
	}
	if src.Keycloak.IssuerURL != "" {
		dst.Keycloak.IssuerURL = src.Keycloak.IssuerURL
	}
	if src.Keycloak.ClientID != "" {
		dst.Keycloak.ClientID = src.Keycloak.ClientID
	}
	if len(src.Keycloak.Scopes) > 0 {
		dst.Keycloak.Scopes = src.Keycloak.Scopes
	}
	if src.EntraID.IssuerURL != "" {
		dst.EntraID.IssuerURL = src.EntraID.IssuerURL
	}
	if src.EntraID.ClientID != "" {
		dst.EntraID.ClientID = src.EntraID.ClientID
	}
	if len(src.EntraID.Scopes) > 0 {
		dst.EntraID.Scopes = src.EntraID.Scopes
	}
	if src.FlashBlade.STSEndpoint != "" {
		dst.FlashBlade.STSEndpoint = src.FlashBlade.STSEndpoint
	}
	if src.FlashBlade.DataEndpoint != "" {
		dst.FlashBlade.DataEndpoint = src.FlashBlade.DataEndpoint
	}
	if src.FlashBlade.RoleARN != "" {
		dst.FlashBlade.RoleARN = src.FlashBlade.RoleARN
	}
	if src.FlashBlade.Account != "" {
		dst.FlashBlade.Account = src.FlashBlade.Account
	}
	if src.S3.TestBucket != "" {
		dst.S3.TestBucket = src.S3.TestBucket
	}
	if src.S3.TestKeyPrefix != "" {
		dst.S3.TestKeyPrefix = src.S3.TestKeyPrefix
	}
	if src.TLS.Insecure {
		dst.TLS.Insecure = src.TLS.Insecure
	}
	if src.TLS.CACert != "" {
		dst.TLS.CACert = src.TLS.CACert
	}
	if src.FlashBlade.Duration != 0 {
		dst.FlashBlade.Duration = src.FlashBlade.Duration
	}
	if src.FlashBlade.ArnFormat != "" {
		dst.FlashBlade.ArnFormat = src.FlashBlade.ArnFormat
	}
	if len(src.OIDCProviders) > 0 {
		if dst.OIDCProviders == nil {
			dst.OIDCProviders = make(map[string]string)
		}
		for k, v := range src.OIDCProviders {
			dst.OIDCProviders[k] = v
		}
	}
}

// DetectIDP determines which IDP to use based on the --idp flag value and
// which config sections are populated. Returns "okta", "keycloak", or "entraid".
func DetectIDP(cfg *TOMLConfig, flagIDP string) (string, error) {
	hasOkta := cfg.Okta.TenantURL != "" || cfg.Okta.ClientID != ""
	hasKeycloak := cfg.Keycloak.IssuerURL != "" || cfg.Keycloak.ClientID != ""
	hasEntraID := cfg.EntraID.IssuerURL != "" || cfg.EntraID.ClientID != ""

	if flagIDP != "" {
		switch flagIDP {
		case "okta":
			if !hasOkta {
				return "", fmt.Errorf("--idp okta specified but no [okta] section in config")
			}
			return "okta", nil
		case "keycloak":
			if !hasKeycloak {
				return "", fmt.Errorf("--idp keycloak specified but no [keycloak] section in config")
			}
			return "keycloak", nil
		case "entraid":
			if !hasEntraID {
				return "", fmt.Errorf("--idp entraid specified but no [entraid] section in config")
			}
			return "entraid", nil
		default:
			return "", fmt.Errorf("unknown IDP %q (supported: okta, keycloak, entraid)", flagIDP)
		}
	}

	populated := []string{}
	if hasOkta {
		populated = append(populated, "[okta]")
	}
	if hasKeycloak {
		populated = append(populated, "[keycloak]")
	}
	if hasEntraID {
		populated = append(populated, "[entraid]")
	}

	if len(populated) > 1 {
		return "", fmt.Errorf("multiple IDPs configured (%s), use --idp to select", strings.Join(populated, ", "))
	}
	if hasEntraID {
		return "entraid", nil
	}
	if hasKeycloak {
		return "keycloak", nil
	}
	return "okta", nil
}

// LoadFromFile reads a single TOML config file and returns a flat steps.Config.
func LoadFromFile(path string) (*steps.Config, error) {
	tc, err := loadTOML(path)
	if err != nil {
		return nil, err
	}
	return tc.ToStepsConfig(), nil
}

// ResolveConfig loads and merges configs in priority order:
// home < local < explicit. Paths that are empty strings are skipped.
// Returns the merged result as a flat *steps.Config.
func ResolveConfig(homePath, localPath, explicitPath string) (*steps.Config, error) {
	merged := &TOMLConfig{}

	for _, path := range []string{homePath, localPath, explicitPath} {
		if path == "" {
			continue
		}
		tc, err := loadTOML(path)
		if err != nil {
			return nil, err
		}
		MergeTOML(merged, tc)
	}

	return merged.ToStepsConfig(), nil
}

// ApplyOverrides writes non-zero flag values into the TOMLConfig, allowing
// CLI flags to override file-based configuration.
func ApplyOverrides(cfg *TOMLConfig, flags *FlagOverrides) {
	if flags == nil {
		return
	}
	if flags.OktaURL != "" {
		cfg.Okta.TenantURL = flags.OktaURL
	}
	if flags.OktaClientID != "" {
		cfg.Okta.ClientID = flags.OktaClientID
	}
	if flags.STSEndpoint != "" {
		cfg.FlashBlade.STSEndpoint = flags.STSEndpoint
	}
	if flags.DataEndpoint != "" {
		cfg.FlashBlade.DataEndpoint = flags.DataEndpoint
	}
	if flags.RoleARN != "" {
		cfg.FlashBlade.RoleARN = flags.RoleARN
	}
	if flags.Account != "" {
		cfg.FlashBlade.Account = flags.Account
	}
	if flags.Bucket != "" {
		cfg.S3.TestBucket = flags.Bucket
	}
	if flags.KeyPrefix != "" {
		cfg.S3.TestKeyPrefix = flags.KeyPrefix
	}
	if flags.Insecure {
		cfg.TLS.Insecure = flags.Insecure
	}
	if flags.CACert != "" {
		cfg.TLS.CACert = flags.CACert
	}
	if flags.Duration != 0 {
		cfg.FlashBlade.Duration = flags.Duration
	}
	if flags.Token != "" {
		cfg.PreSuppliedToken = flags.Token
	}
}

// ToStepsConfig converts a TOMLConfig to the flat steps.Config type,
// applying defaults for any unset required fields.
func (tc *TOMLConfig) ToStepsConfig() *steps.Config {
	scopes := tc.Okta.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "groups"}
	}

	keycloakScopes := tc.Keycloak.Scopes
	if len(keycloakScopes) == 0 {
		keycloakScopes = []string{"openid", "profile"}
	}

	entraIDScopes := tc.EntraID.Scopes
	if len(entraIDScopes) == 0 {
		entraIDScopes = []string{"openid", "profile"}
	}

	duration := tc.FlashBlade.Duration
	if duration == 0 {
		duration = 3600
	}

	return &steps.Config{
		OktaTenantURL:     tc.Okta.TenantURL,
		OktaClientID:      tc.Okta.ClientID,
		OktaScopes:        scopes,
		KeycloakIssuerURL: tc.Keycloak.IssuerURL,
		KeycloakClientID:  tc.Keycloak.ClientID,
		KeycloakScopes:    keycloakScopes,
		EntraIDIssuerURL:  tc.EntraID.IssuerURL,
		EntraIDClientID:   tc.EntraID.ClientID,
		EntraIDScopes:     entraIDScopes,
		STSEndpoint:       tc.FlashBlade.STSEndpoint,
		DataEndpoint:      tc.FlashBlade.DataEndpoint,
		RoleARN:           tc.FlashBlade.RoleARN,
		Account:           tc.FlashBlade.Account,
		TestBucket:        tc.S3.TestBucket,
		TestKeyPrefix:     tc.S3.TestKeyPrefix,
		Insecure:          tc.TLS.Insecure,
		CACert:            tc.TLS.CACert,
		ContinueOnError:   tc.ContinueOnError,
		PreSuppliedToken:  tc.PreSuppliedToken,
		Duration:          duration,
	}
}

// PromptMissing interactively asks for any required fields that are empty.
// selectedIDP must be "okta", "keycloak", or "entraid"; it controls which IDP fields are prompted.
func PromptMissing(cfg *TOMLConfig, reader *bufio.Reader, selectedIDP string) error {
	switch selectedIDP {
	case "keycloak":
		if cfg.Keycloak.IssuerURL == "" {
			fmt.Print("Keycloak issuer URL (e.g. https://keycloak.example.com/realms/my-realm): ")
			val, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("read keycloak issuer url: %w", err)
			}
			cfg.Keycloak.IssuerURL = trimNewline(val)
		}
		if cfg.Keycloak.ClientID == "" {
			fmt.Print("Keycloak client ID: ")
			val, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("read keycloak client id: %w", err)
			}
			cfg.Keycloak.ClientID = trimNewline(val)
		}
	case "entraid":
		if cfg.EntraID.IssuerURL == "" {
			fmt.Print("EntraID issuer URL (e.g. https://login.microsoftonline.com/<tenant-id>/v2.0): ")
			val, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("read entraid issuer url: %w", err)
			}
			cfg.EntraID.IssuerURL = trimNewline(val)
		}
		if cfg.EntraID.ClientID == "" {
			fmt.Print("EntraID client ID: ")
			val, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("read entraid client id: %w", err)
			}
			cfg.EntraID.ClientID = trimNewline(val)
		}
	default: // okta
		if cfg.Okta.TenantURL == "" {
			fmt.Print("Okta tenant URL: ")
			val, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("read okta tenant url: %w", err)
			}
			cfg.Okta.TenantURL = trimNewline(val)
		}
		if cfg.Okta.ClientID == "" {
			fmt.Print("Okta client ID: ")
			val, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("read okta client id: %w", err)
			}
			cfg.Okta.ClientID = trimNewline(val)
		}
	}
	if cfg.FlashBlade.STSEndpoint == "" {
		fmt.Print("FlashBlade STS endpoint: ")
		val, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read sts endpoint: %w", err)
		}
		cfg.FlashBlade.STSEndpoint = trimNewline(val)
	}
	if cfg.FlashBlade.RoleARN == "" {
		fmt.Print("Role ARN: ")
		val, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read role arn: %w", err)
		}
		cfg.FlashBlade.RoleARN = trimNewline(val)
	}
	return nil
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// SniffArnFormat returns "prn" or "aws" based on the prefix of the given ARN/PRN.
// Defaults to "aws" if the prefix is unrecognized or the input is empty.
func SniffArnFormat(arn string) string {
	if strings.HasPrefix(arn, "prn::") {
		return "prn"
	}
	if strings.HasPrefix(arn, "arn:aws:") {
		return "aws"
	}
	return "aws"
}
