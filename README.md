# fbsts — FlashBlade STS Validator

A CLI tool for validating STS (Security Token Service) functionality on Pure Storage FlashBlade arrays. It performs a complete `AssumeRoleWithWebIdentity` flow — authenticating with Okta via OIDC, obtaining temporary S3 credentials from the FlashBlade STS endpoint, and validating them with a full S3 CRUD cycle.

Every piece of data exchanged during the flow is displayed in rich terminal output, making it useful for troubleshooting, validation, and live demos.

## Features

- **End-to-end STS validation** — Okta OIDC → FlashBlade STS → S3 CRUD in a single command
- **Device code auth** — CLI-friendly Okta authentication with automatic browser launch
- **Rich visual output** — Styled terminal panels showing tokens, claims, credentials, and API responses
- **Subway-map demo mode** — Live TUI with a metro-style flow visualization for presentations
- **Secret masking** — Secrets masked by default, `--unmask` to reveal when debugging
- **Self-signed cert support** — `--insecure` and `--ca-cert` for test/lab FlashBlade environments
- **Single binary** — Zero runtime dependencies, cross-platform (macOS, Linux, Windows)

## Installation

### Download a release

Download the latest binary for your platform from the [Releases](../../releases) page.

```bash
# macOS (Apple Silicon)
tar -xzf fbsts_*_darwin_arm64.tar.gz
chmod +x fbsts
sudo mv fbsts /usr/local/bin/

# macOS (Intel)
tar -xzf fbsts_*_darwin_amd64.tar.gz
chmod +x fbsts
sudo mv fbsts /usr/local/bin/

# Linux (amd64)
tar -xzf fbsts_*_linux_amd64.tar.gz
chmod +x fbsts
sudo mv fbsts /usr/local/bin/
```

### Build from source

Requires Go 1.22+.

```bash
git clone <this-repo>
cd rp-fbstsvalidator
make build            # build for current platform
make build-all        # build for all platforms (output in build/)
```

## Quick Start

```bash
# 1. Generate a config file
fbsts init

# 2. Edit with your environment details
vim .fbsts.toml

# 3. Run the validation
fbsts validate --insecure
```

Or pass everything via flags:

```bash
fbsts validate \
  --okta-url https://myorg.okta.com \
  --client-id 0oa1b2c3d4e5f6g7h8i9 \
  --sts-endpoint https://fb-sts.example.com \
  --data-endpoint https://fb-data.example.com \
  --role-arn "arn:aws:iam::123456789:role/my-role" \
  --bucket validation-test \
  --insecure
```

## What It Does

The tool executes four steps in sequence:

### Step 1: Okta Device Auth

Authenticates with Okta using the [device authorization grant](https://developer.okta.com/docs/guides/device-authorization-grant/main/). The tool displays a URL and code, opens your browser automatically, and waits for you to authorize. No passwords are handled by the tool.

### Step 2: Token Decode

Decodes the OIDC JWT ID token and displays the header and claims. Trust-policy-relevant claims (`iss`, `sub`, `aud`, `groups`) are highlighted. This step does not verify the signature — FlashBlade handles that.

### Step 3: STS AssumeRoleWithWebIdentity

Sends the OIDC token to the FlashBlade STS VIP endpoint with `AssumeRoleWithWebIdentity`. On success, receives temporary credentials: `AccessKeyId`, `SecretAccessKey`, `SessionToken`, and expiration.

### Step 4: S3 Validate (CRUD)

Uses the temporary credentials to perform a full S3 CRUD cycle against the FlashBlade Data VIP:

1. **ListBuckets** — confirms credential validity
2. **PutObject** — writes a test object
3. **GetObject** — reads it back and verifies content via SHA-256
4. **DeleteObject** — cleans up

Each operation is displayed with its HTTP status, timing, and pass/fail result.

## Configuration

### Config File

Generate a template with `fbsts init`, then edit `.fbsts.toml`:

```toml
[okta]
tenant_url = "https://myorg.okta.com"
client_id = "0oa1b2c3d4e5f6g7h8i9"
scopes = ["openid", "profile", "groups"]

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
```

### Config Resolution Order

Values are resolved in this priority (highest first):

1. CLI flags
2. Local `./.fbsts.toml`
3. Home `~/.fbsts.toml`
4. Interactive prompt (for missing required values)

### CLI Reference

```
fbsts validate [flags]    Run the full STS validation flow
fbsts init                Generate a sample .fbsts.toml
fbsts version             Print version information
```

#### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--okta-url` | Okta tenant URL | |
| `--client-id` | Okta OIDC application client ID | |
| `--scopes` | OIDC scopes (comma-separated) | `openid,profile,groups` |
| `--sts-endpoint` | FlashBlade STS VIP URL | |
| `--data-endpoint` | FlashBlade S3 Data VIP URL | |
| `--role-arn` | Role ARN to assume | |
| `--account` | FlashBlade object store account | |
| `--bucket` | S3 test bucket name | |
| `--key-prefix` | Test object key prefix | `fbsts-validate/` |
| `--duration` | STS session duration (seconds) | `3600` |
| `--insecure` | Skip TLS certificate verification | `false` |
| `--ca-cert` | Path to custom CA certificate PEM | |
| `--continue-on-error` | Continue through all steps even if one fails | `false` |
| `--token` | Pre-supplied JWT (skips Okta device auth) | |
| `--unmask` | Show SecretAccessKey and SessionToken in clear text | `false` |
| `--renderer` | Renderer style: `panel` or `subway` | `panel` |
| `--demo` | Demo mode: subway renderer + inter-step pacing | `false` |
| `--config` | Explicit config file path | |

## Display Modes

### Panel Mode (default)

Each step gets a bordered terminal panel with key-value fields, sub-step results, and timing. Good for everyday validation and troubleshooting.

```bash
fbsts validate
```

### Subway-Map Mode

A live TUI displaying the validation flow as a vertical metro map. Each step is a station that transitions from pending (gray) to running (yellow) to complete (green) or failed (red). S3 operations appear as branch stations.

```bash
fbsts validate --renderer subway
```

### Demo Mode

Subway-map renderer with 800ms pacing between steps for presentations. The audience sees each station light up with a brief pause between transitions.

```bash
fbsts validate --demo
```

## Secret Masking

By default, sensitive values are masked in the output:

| Tier | Treatment | Examples |
|------|-----------|---------|
| **Shown** | Displayed as-is | AccessKeyId, JWT claims, role ARN, endpoints, HTTP status codes |
| **Truncated** | Partial display | Raw JWT: `eyJhbG...<masked>...kF9xQ` |
| **Masked** | `**********` | SecretAccessKey, SessionToken |

Use `--unmask` to show SecretAccessKey and SessionToken in clear text when debugging credential issues.

## TLS / Self-Signed Certificates

Many test FlashBlade arrays use self-signed certificates. Two options:

```bash
# Skip all TLS verification (shows a warning banner)
fbsts validate --insecure

# Provide a custom CA certificate
fbsts validate --ca-cert /path/to/flashblade-ca.pem
```

Both flags apply to all HTTPS connections: Okta, STS VIP, and Data VIP.

## Error Handling

When a step fails, the tool displays the full error including HTTP status, error code, raw response, and a diagnostic hint suggesting what to check.

**Fail-fast (default):** Stops at the first failure.

**Continue-on-error:** Runs all steps and reports a pass/fail summary.

```bash
fbsts validate --continue-on-error
```

### Common Errors

| Error | Likely Cause |
|-------|-------------|
| Okta `invalid_client` | Client ID is wrong or the app isn't configured for device code grant |
| STS `AccessDenied` | Role trust policy doesn't match your token's claims (check `aud`, `sub`, `groups`) |
| STS `InvalidIdentityToken` | Token expired or FlashBlade can't reach Okta's JWKS endpoint |
| S3 `403 Forbidden` | Credentials work but the role's access policy doesn't grant the S3 operation |
| TLS certificate error | FlashBlade uses a self-signed cert — use `--insecure` or `--ca-cert` |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All steps passed |
| `1` | A step failed |
| `2` | Configuration error |

## Okta Setup

For the tool to work, your Okta tenant needs:

1. **An OIDC application** configured with the **Device Authorization** grant type
2. **A `groups` scope** on the authorization server (Security > API > Authorization Servers > Scopes > Add Scope)
3. **A `groups` claim** on the authorization server (Claims > Add Claim with value type "Groups", filter "Matches regex `.*`", included in ID Token)
4. **User and group assignments** on the application

The tool requests `openid`, `profile`, and `groups` scopes by default. Customize with `--scopes` or the config file.

## FlashBlade Setup

The FlashBlade side requires:

1. **OIDC Identity Provider trust** — configured under Settings > Single Sign-On with your Okta tenant's OIDC discovery URL
2. **STS VIP** — a network interface on a data subnet with service type `sts`
3. **Object store role** — under Storage > Object Store > Accounts > [account] > Roles
4. **Trust policy rule** — on the role, with action `sts:AssumeRoleWithWebIdentity`, principal referencing the OIDC provider, and conditions matching JWT claims (`jwt:aud`, `jwt:groups`, etc.)

For detailed FlashBlade configuration, see the [Object Identity Federation Quick Start Guide](https://support.purestorage.com/bundle/m_flashblade_object_services/page/FlashBlade/Purity_FB/FlashBlade_Object_Services/topics/c_quick_start_guide_object_identity_federation_on_flashblade.html).

## Pre-supplied Token

For automation or when you've already obtained a token through another mechanism:

```bash
fbsts validate --token "eyJhbGciOi..." --sts-endpoint https://fb-sts.example.com ...
```

This skips the Okta device auth step entirely and uses the provided JWT directly for the STS call.

## Development

```bash
make build        # build for current platform
make build-all    # build all platforms to build/
make test         # run all tests
make vet          # run go vet
make clean        # remove build artifacts
make help         # show all targets
```

### Releasing

Releases are automated via GitHub Actions. Push a tag to create a release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

GoReleaser builds binaries for all platforms, creates archives with checksums, and uploads them to GitHub Releases.

## Architecture

The tool uses a pipeline architecture with four pluggable steps:

```
CLI → Config → Runner → [OktaDeviceAuth → TokenDecode → STSAssume → S3Validate] → Renderer
```

- **Steps** implement a common `Step` interface and pass state via a shared `FlowContext`
- **Renderers** implement a `Renderer` interface — `PanelRenderer` (lipgloss panels) and `SubwayRenderer` (bubbletea TUI) are included
- **SigV4 signing** is hand-rolled (no AWS SDK) for full visibility into request/response details
- **Config** loads from TOML files with CLI flag overrides and interactive prompts for missing values

## License

Internal tool — Pure Storage proprietary.
