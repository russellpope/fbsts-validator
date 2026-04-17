package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/pure-experimental/rp-fbstsvalidator/internal/config"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/idp"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/render"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/runner"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

var version = "dev"

var flags config.FlagOverrides
var configPath string
var flagScopes []string
var flagContinueOnError bool
var flagRenderer string
var flagUnmask bool
var flagIDP string
var flagEmitToken string

func main() {
	rootCmd := &cobra.Command{
		Use:   "fbsts",
		Short: "FlashBlade STS Validator",
		Long:  "Validates STS (Security Token Service) functionality on Pure Storage FlashBlade arrays for object storage.",
	}

	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Run the full STS validation flow",
		Long: "Authenticates with an identity provider via device code flow, obtains temporary credentials via AssumeRoleWithWebIdentity, and validates them with S3 CRUD operations.",
		RunE:  runValidate,
	}

	// Okta flags
	validateCmd.Flags().StringVar(&flags.OktaURL, "okta-url", "", "Okta tenant URL (e.g. https://myorg.okta.com)")
	validateCmd.Flags().StringVar(&flags.OktaClientID, "client-id", "", "Okta OIDC client ID")
	validateCmd.Flags().StringSliceVar(&flagScopes, "scopes", nil, "OIDC scopes (comma-separated)")

	// FlashBlade flags
	validateCmd.Flags().StringVar(&flags.STSEndpoint, "sts-endpoint", "", "FlashBlade STS endpoint URL")
	validateCmd.Flags().StringVar(&flags.DataEndpoint, "data-endpoint", "", "FlashBlade S3 data endpoint URL")
	validateCmd.Flags().StringVar(&flags.RoleARN, "role-arn", "", "IAM role ARN for AssumeRoleWithWebIdentity")
	validateCmd.Flags().StringVar(&flags.Account, "account", "", "FlashBlade account name")

	// S3 flags
	validateCmd.Flags().StringVar(&flags.Bucket, "bucket", "", "S3 test bucket name")
	validateCmd.Flags().StringVar(&flags.KeyPrefix, "key-prefix", "", "S3 object key prefix for test objects")

	// TLS flags
	validateCmd.Flags().BoolVar(&flags.Insecure, "insecure", false, "Skip TLS certificate verification")
	validateCmd.Flags().StringVar(&flags.CACert, "ca-cert", "", "Path to PEM-encoded CA certificate bundle")

	// Behavior flags
	validateCmd.Flags().BoolVar(&flagContinueOnError, "continue-on-error", false, "Continue pipeline on step failure")
	validateCmd.Flags().StringVar(&flags.Token, "token", "", "Pre-supplied OIDC token (skips Okta device auth)")
	validateCmd.Flags().IntVar(&flags.Duration, "duration", 0, "Requested credential duration in seconds")
	validateCmd.Flags().BoolVar(&flagUnmask, "unmask", false, "Show SecretAccessKey and SessionToken in clear text")

	// IDP flags
	validateCmd.Flags().StringVar(&flagIDP, "idp", "", "Identity provider: okta or keycloak (auto-detected if omitted)")
	validateCmd.Flags().StringVar(&flagEmitToken, "emit-token", "", "Write raw JWT to file (no decoration)")

	// Config flag
	validateCmd.Flags().StringVar(&configPath, "config", "", "Path to a .fbsts.toml config file")

	// Renderer flags
	validateCmd.Flags().StringVar(&flagRenderer, "renderer", "subway", "Renderer style: panel or subway")

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a sample .fbsts.toml config file",
		RunE:  runInit,
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("fbsts %s\n", version)
		},
	}

	rootCmd.AddCommand(validateCmd, initCmd, versionCmd, newDecodeCmd(), newTrustPolicyCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runValidate(cmd *cobra.Command, args []string) error {
	// 1. Determine config paths.
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = ""
	}
	homePath := ""
	if homeDir != "" {
		homePath = filepath.Join(homeDir, ".fbsts.toml")
		if _, err := os.Stat(homePath); os.IsNotExist(err) {
			homePath = ""
		}
	}
	localPath := ".fbsts.toml"
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		localPath = ""
	}

	// 2. Build a merged TOMLConfig from config files.
	merged := &config.TOMLConfig{}
	for _, path := range []string{homePath, localPath, configPath} {
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open config %q: %w", path, err)
		}
		var tc config.TOMLConfig
		_, decodeErr := toml.NewDecoder(f).Decode(&tc)
		f.Close()
		if decodeErr != nil {
			return fmt.Errorf("parse config %q: %w", path, decodeErr)
		}
		config.MergeTOML(merged, &tc)
	}

	// 3. Check if --insecure was explicitly set.
	if cmd.Flags().Changed("insecure") {
		flags.Insecure = true
	}

	// 4. Apply CLI flag overrides.
	config.ApplyOverrides(merged, &flags)

	// 5. Apply continue-on-error and scopes flags.
	merged.ContinueOnError = flagContinueOnError
	if len(flagScopes) > 0 {
		merged.Okta.Scopes = flagScopes
	}

	// 6. Detect which IDP to use.
	selectedIDP, err := config.DetectIDP(merged, flagIDP)
	if err != nil {
		return fmt.Errorf("IDP selection: %w", err)
	}

	// 7. Prompt for missing values (skip IDP prompts if --token provided).
	reader := bufio.NewReader(os.Stdin)
	if flags.Token != "" {
		if selectedIDP == "okta" {
			if merged.Okta.TenantURL == "" {
				merged.Okta.TenantURL = "(token-provided)"
			}
			if merged.Okta.ClientID == "" {
				merged.Okta.ClientID = "(token-provided)"
			}
		} else {
			if merged.Keycloak.IssuerURL == "" {
				merged.Keycloak.IssuerURL = "(token-provided)"
			}
			if merged.Keycloak.ClientID == "" {
				merged.Keycloak.ClientID = "(token-provided)"
			}
		}
	}
	if err := config.PromptMissing(merged, reader, selectedIDP); err != nil {
		return fmt.Errorf("prompting for config: %w", err)
	}

	// 8. Convert to steps config.
	cfg := merged.ToStepsConfig()

	// 9. Set pre-supplied token, unmask flag, and emit-token path.
	if flags.Token != "" {
		cfg.PreSuppliedToken = flags.Token
	}
	cfg.Unmask = flagUnmask
	cfg.EmitTokenPath = flagEmitToken

	// 10. Create HTTP client.
	client, err := config.NewHTTPClient(cfg.Insecure, cfg.CACert)
	if err != nil {
		return fmt.Errorf("creating HTTP client: %w", err)
	}

	// 11. Build the IDP authenticator.
	var auth idp.IDPAuthenticator
	switch selectedIDP {
	case "okta":
		auth = idp.NewOktaAuthenticator(cfg.OktaTenantURL, cfg.OktaClientID, cfg.OktaScopes, client)
	case "keycloak":
		auth = idp.NewKeycloakAuthenticator(cfg.KeycloakIssuerURL, cfg.KeycloakClientID, cfg.KeycloakScopes, client)
	}

	// 12. Create renderer based on flags.
	var rend render.Renderer
	stepNames := []string{"DeviceAuth", "TokenDecode", "STSAssume", "S3Validate"}
	switch flagRenderer {
	case "panel":
		rend = render.NewPanelRenderer(os.Stdout)
	default:
		sr := render.NewSubwayRenderer(stepNames)
		sr.Start()
		defer sr.Stop()
		rend = sr
	}

	// 13. Show TLS warning if insecure.
	if cfg.Insecure {
		rend.RenderWarning("TLS certificate verification is disabled (--insecure). Do not use in production.")
	}

	// 14. Build pipeline.
	pipeline := []steps.Step{
		steps.NewDeviceAuthStep(auth),
		steps.NewTokenDecodeStep(),
		steps.NewSTSAssumeStep(),
		steps.NewS3ValidateStep(),
	}

	// 15. Create FlowContext and run via runner.Run.
	flowCtx := steps.NewFlowContext(cfg, client)
	r := runner.New(rend)
	if flagRenderer != "panel" {
		r.DemoPace = 800 * time.Millisecond
	}
	if err := r.Run(flowCtx, pipeline, cfg.ContinueOnError); err != nil {
		emitTokens(cfg.EmitTokenPath, flowCtx)
		return err
	}

	// 16. Write tokens to file if --emit-token was set.
	emitTokens(cfg.EmitTokenPath, flowCtx)

	return nil
}

// emitTokens writes the ID token and access token to files if --emit-token was set.
// Given path "token.jwt", writes ID token to "token.jwt" and access token to "token-access.jwt".
func emitTokens(path string, ctx *steps.FlowContext) {
	if path == "" {
		return
	}
	writeFile(path, ctx.IDToken, "ID token")
	ext := filepath.Ext(path)
	accessPath := strings.TrimSuffix(path, ext) + "-access" + ext
	writeFile(accessPath, ctx.AccessToken, "access token")
}

func writeFile(path, content, label string) {
	if content == "" {
		return
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write %s to %s: %v\n", label, path, err)
		return
	}
	fmt.Printf("  %s written to %s\n", strings.ToUpper(label[:1])+label[1:], path)
}

func runInit(cmd *cobra.Command, args []string) error {
	const targetPath = ".fbsts.toml"

	// 1. Check if .fbsts.toml already exists.
	if _, err := os.Stat(targetPath); err == nil {
		return fmt.Errorf("%s already exists; remove it first or edit it directly", targetPath)
	}

	// 2. Write sample config file.
	const sampleConfig = `# FlashBlade STS Validator Configuration
# Copy this to ~/.fbsts.toml or ./.fbsts.toml and fill in your values.
# CLI flags override config file values. See: fbsts validate --help
# If both [okta] and [keycloak] are configured, use --idp to select.

[okta]
tenant_url = "https://myorg.okta.com"
client_id = "0oa1b2c3d4e5f6g7h8i9"
scopes = ["openid", "profile", "groups"]

# [keycloak]
# issuer_url = "https://keycloak.example.com/realms/my-realm"
# client_id = "my-keycloak-client"
# scopes = ["openid", "profile"]

[flashblade]
sts_endpoint = "https://fb-sts.example.com"
data_endpoint = "https://fb-data.example.com"
role_arn = "arn:aws:iam::123456789:role/my-role"
account = "myaccount"
# STS session duration in seconds (default: 3600)
# duration = 3600

[s3]
test_bucket = "validation-test"
test_key_prefix = "fbsts-validate/"

[tls]
insecure = false
ca_cert = ""

# OIDC provider mapping (used by ` + "`" + `fbsts trust-policy` + "`" + ` to resolve the principal
# from the JWT's iss claim). Keys are issuer URLs; values are the OIDC provider
# names registered on the FlashBlade.
# [oidc_providers]
# "https://myorg.okta.com" = "okta-for-object"
# "https://keycloak.example.com/realms/my-realm" = "keycloak-realm"
`

	if err := os.WriteFile(targetPath, []byte(sampleConfig), 0600); err != nil {
		return fmt.Errorf("writing %s: %w", targetPath, err)
	}

	// 3. Print confirmation.
	fmt.Printf("Created %s — edit it with your IDP and FlashBlade settings.\n", targetPath)
	return nil
}
