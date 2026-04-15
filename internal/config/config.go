package config

import (
	"bufio"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

// OktaConfig holds Okta-related TOML settings.
type OktaConfig struct {
	TenantURL string   `toml:"tenant_url"`
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
	Okta       OktaConfig       `toml:"okta"`
	FlashBlade FlashBladeConfig `toml:"flashblade"`
	S3         S3Config         `toml:"s3"`
	TLS        TLSConfig        `toml:"tls"`

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

// mergeTOML merges src into dst, overwriting only non-zero values from src.
func mergeTOML(dst, src *TOMLConfig) {
	if src.Okta.TenantURL != "" {
		dst.Okta.TenantURL = src.Okta.TenantURL
	}
	if src.Okta.ClientID != "" {
		dst.Okta.ClientID = src.Okta.ClientID
	}
	if len(src.Okta.Scopes) > 0 {
		dst.Okta.Scopes = src.Okta.Scopes
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
		mergeTOML(merged, tc)
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

	duration := tc.FlashBlade.Duration
	if duration == 0 {
		duration = 3600
	}

	return &steps.Config{
		OktaTenantURL:    tc.Okta.TenantURL,
		OktaClientID:     tc.Okta.ClientID,
		OktaScopes:       scopes,
		STSEndpoint:      tc.FlashBlade.STSEndpoint,
		DataEndpoint:     tc.FlashBlade.DataEndpoint,
		RoleARN:          tc.FlashBlade.RoleARN,
		Account:          tc.FlashBlade.Account,
		TestBucket:       tc.S3.TestBucket,
		TestKeyPrefix:    tc.S3.TestKeyPrefix,
		Insecure:         tc.TLS.Insecure,
		CACert:           tc.TLS.CACert,
		ContinueOnError:  tc.ContinueOnError,
		PreSuppliedToken: tc.PreSuppliedToken,
		Duration:         duration,
	}
}

// PromptMissing interactively asks for any required fields that are empty.
func PromptMissing(cfg *TOMLConfig, reader *bufio.Reader) error {
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
