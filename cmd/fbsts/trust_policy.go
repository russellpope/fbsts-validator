package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/pure-experimental/rp-fbstsvalidator/internal/config"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/trustpolicy"
)

func newTrustPolicyCmd() *cobra.Command {
	var (
		flagPrincipal     string
		flagPrincipalARN  string
		flagRuleName      string
		flagEffect        string
		flagAction        string
		flagConditions    []string
		flagIncludeClaims []string
		flagInteractive   bool
		flagFormat        string
		flagOutput        string
		flagConfig        string
	)

	cmd := &cobra.Command{
		Use:   "trust-policy [<jwt-file>]",
		Short: "Generate a FlashBlade trust policy rule from a JWT or flags",
		Long: `Generate a single FlashBlade trust policy rule as JSON.

Three modes:
  - <jwt-file>                    targeted: derive conditions from the JWT's claims
  - <jwt-file> --interactive      walk each claim with prompts
  - --condition ... (no JWT)      flag-driven (no JWT)

Output is the FlashBlade rule-add body shape by default. Use --format iam
to emit an AWS IAM policy document instead.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// 1. Load merged config.
			merged, err := loadMergedConfig(flagConfig)
			if err != nil {
				return err
			}

			// 2. Parse all --condition DSL flags.
			conditions := make([]trustpolicy.Condition, 0, len(flagConditions))
			for _, raw := range flagConditions {
				c, err := trustpolicy.ParseCondition(raw)
				if err != nil {
					return err
				}
				conditions = append(conditions, *c)
			}

			// 3. Build PrincipalResolver from flags + config.
			arnFormat := merged.FlashBlade.ArnFormat
			if arnFormat == "" {
				arnFormat = config.SniffArnFormat(merged.FlashBlade.RoleARN)
			}
			resolver := &trustpolicy.PrincipalResolver{
				FlagARN:        flagPrincipalARN,
				FlagName:       flagPrincipal,
				ProvidersByISS: merged.OIDCProviders,
				ARNFormat:      arnFormat,
				RoleARN:        merged.FlashBlade.RoleARN,
			}

			// 4. Read the JWT if a file was supplied.
			token := ""
			if len(args) == 1 {
				raw, err := os.ReadFile(args[0])
				if err != nil {
					return fmt.Errorf("reading %s: %w", args[0], err)
				}
				token = string(raw)
			}

			// 5. Build Inputs.
			in := trustpolicy.Inputs{
				Token:         token,
				Conditions:    conditions,
				IncludeClaims: flagIncludeClaims,
				Resolver:      resolver,
				Effect:        flagEffect,
				RuleName:      flagRuleName,
			}
			if flagInteractive {
				in.Reader = bufio.NewReader(os.Stdin)
				in.Writer = os.Stderr
			}

			// 6. Dispatch by mode.
			var rule *trustpolicy.Rule
			switch {
			case len(args) == 1 && flagInteractive:
				rule, err = trustpolicy.Interactive(in)
			case len(args) == 1:
				rule, err = trustpolicy.FromJWT(in)
			case len(args) == 0 && len(conditions) > 0:
				rule, err = trustpolicy.Build(in)
			default:
				return fmt.Errorf("no JWT file and no --condition flags — supply at least one (see --help)")
			}
			if err != nil {
				return err
			}

			// 7. Override action if explicitly set.
			if flagAction != "" {
				rule.Action = flagAction
			}

			// 8. Encode.
			var out []byte
			switch flagFormat {
			case "iam":
				out, err = trustpolicy.EncodeIAMDocument([]trustpolicy.Rule{*rule})
			default:
				out, err = trustpolicy.EncodeRuleBody(rule)
			}
			if err != nil {
				return err
			}

			// 9. Write to stdout or file.
			if flagOutput != "" {
				if err := os.WriteFile(flagOutput, out, 0600); err != nil {
					return fmt.Errorf("writing -o %q: %w", flagOutput, err)
				}
				fmt.Fprintf(os.Stderr, "  wrote %s\n", flagOutput)
			} else {
				fmt.Println(string(out))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&flagPrincipal, "principal", "", "OIDC provider name on FlashBlade (e.g. okta-for-object)")
	cmd.Flags().StringVar(&flagPrincipalARN, "principal-arn", "", "Full federated principal ARN/PRN (overrides --principal)")
	cmd.Flags().StringVar(&flagRuleName, "rule-name", "", "Rule name (default: auto-generated)")
	cmd.Flags().StringVar(&flagEffect, "effect", "allow", "Effect: allow or deny")
	cmd.Flags().StringVar(&flagAction, "action", "", "Trust action (default: sts:AssumeRoleWithWebIdentity)")
	// Use StringArrayVar (not StringSliceVar) so values containing commas
	// (e.g. "jwt:groups=any-eq:eng,security") are not split by pflag.
	cmd.Flags().StringArrayVar(&flagConditions, "condition", nil, "Condition in DSL form (repeatable)")
	cmd.Flags().StringArrayVar(&flagIncludeClaims, "include-claim", nil, "JWT claim to include with default operator (repeatable)")
	cmd.Flags().BoolVar(&flagInteractive, "interactive", false, "Walk each JWT claim with prompts")
	cmd.Flags().StringVar(&flagFormat, "format", "rule", "Output format: rule or iam")
	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Write to file (0600) instead of stdout")
	cmd.Flags().StringVar(&flagConfig, "config", "", "Path to a .fbsts.toml config file")

	return cmd
}

// loadMergedConfig discovers home, local, and explicit config files and merges them.
func loadMergedConfig(explicit string) (*config.TOMLConfig, error) {
	homeDir, _ := os.UserHomeDir()
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

	merged := &config.TOMLConfig{}
	for _, p := range []string{homePath, localPath, explicit} {
		if p == "" {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			return nil, fmt.Errorf("open config %q: %w", p, err)
		}
		var tc config.TOMLConfig
		_, err = toml.NewDecoder(f).Decode(&tc)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("parse config %q: %w", p, err)
		}
		mergeTOMLConfig(merged, &tc)
	}
	return merged, nil
}
