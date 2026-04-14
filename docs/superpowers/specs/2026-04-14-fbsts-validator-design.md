# FlashBlade STS Validator (`fbsts`) -- Design Spec

## Overview

A Go CLI tool that validates STS (Security Token Service) functionality on Pure Storage FlashBlade arrays for object storage. The tool performs a complete `AssumeRoleWithWebIdentity` flow using Okta OIDC device code authentication, obtains temporary S3 credentials, and validates them with a full CRUD cycle -- displaying every piece of data exchanged along the way.

The tool is designed for SEs, support engineers, and customers who need to verify that FlashBlade STS is correctly configured and working end-to-end. It produces rich, visual terminal output that shows tokens, claims, credentials, and API responses at each step, making it useful for both troubleshooting and live demos.

## Goals

- Validate the complete `AssumeRoleWithWebIdentity` flow from Okta through STS to S3
- Show everything exchanged during the flow, masking only true secrets
- Distribute as a single static Go binary (no runtime dependencies)
- Support FlashBlade test environments with self-signed certificates
- Architecture that supports future renderer modes (subway-map demo view) and additional auth flows (SAML, other IdPs)

## Non-Goals (for v1)

- SAML authentication flow (`AssumeRoleWithSAML`)
- Identity providers other than Okta
- Interactive TUI (bubbletea) -- lipgloss styling only
- Multi-array validation in a single run
- Continuous monitoring or watch mode

## Architecture

### Pipeline with Step Interface

The tool uses a pipeline architecture where each phase of the STS flow is an independent `Step` implementation. A `Runner` executes steps in sequence, passing a shared `FlowContext` between them. A `Renderer` interface decouples all visual output from flow logic.

```
CLI (cobra) → Config (TOML + flags + prompts) → Runner → Steps → Renderer
```

### Core Interfaces

```go
// Step represents a single phase of the STS validation flow.
type Step interface {
    Name() string
    Execute(ctx *FlowContext) (*StepResult, error)
}

// StepResult contains structured output from a step for rendering.
type StepResult struct {
    Title    string
    Fields   []Field       // key-value pairs to display
    SubSteps []SubStep     // nested operations (e.g., individual S3 ops)
    Duration time.Duration
}

// Renderer handles all terminal output.
type Renderer interface {
    RenderStepStart(name string)
    RenderStepResult(step Step, result *StepResult)
    RenderStepError(step Step, err error, hint string)
    RenderSummary(results []*StepResult, failures []error)
}
```

### FlowContext

Shared state bag passed between steps:

```go
type FlowContext struct {
    Config         *Config
    HTTPClient     *http.Client     // TLS-configured client

    // Set by OktaDeviceAuth
    IDToken        string           // raw JWT
    AccessToken    string

    // Set by TokenDecode
    TokenHeader    map[string]interface{}
    TokenClaims    map[string]interface{}

    // Set by STSAssume
    AccessKeyId    string
    SecretAccessKey string
    SessionToken   string
    Expiration     time.Time
    AssumedRoleARN string

    // Set by S3Validate
    S3Results      []S3OpResult
}
```

### Components

| Component | Package | Responsibility |
|-----------|---------|----------------|
| CLI | `cmd/fbsts/` | cobra root command, `validate` and `init` subcommands |
| Config | `internal/config/` | TOML loading, flag merging, interactive prompts, TLS transport setup |
| Runner | `internal/runner/` | Pipeline orchestration, `--continue-on-error` handling |
| Steps | `internal/steps/` | Four step implementations (see below) |
| Renderer | `internal/render/` | Renderer interface, PanelRenderer (lipgloss), masking utilities |
| SigV4 | `internal/s3signer/` | AWS Signature Version 4 request signing with session token |

## Steps

### Step 1: OktaDeviceAuth

**Purpose:** Obtain an OIDC ID token from Okta using the device authorization grant flow.

**Process:**
1. Fetch Okta's `/.well-known/openid-configuration` to discover the device authorization and token endpoints
2. POST to the device authorization endpoint with `client_id` and `scope`
3. Display the `verification_uri_complete` and `user_code` to the user
4. Poll the token endpoint at the specified `interval` until authorization is granted or timeout

**Displayed data:**
- Okta discovery URL and discovered endpoints
- Device code (truncated), verification URL, user code
- Poll status (waiting, authorized, expired)
- On success: raw ID token (truncated), access token (truncated), token type, expiry timestamp
- Step timing

**Inputs:** Okta tenant URL, client ID, scopes (from config)
**Outputs to context:** `IDToken`, `AccessToken`

### Step 2: TokenDecode

**Purpose:** Decode the JWT ID token and display its contents for inspection.

**Process:**
1. Split the JWT into header, payload, signature segments
2. Base64-decode header and payload
3. Parse as JSON and display all fields

**Displayed data:**
- Raw JWT with middle section truncated (header.`<masked>`.signature_hint)
- Decoded header: `alg`, `kid`, `typ`
- Decoded claims: all fields, with trust-policy-relevant claims highlighted (`aud`, `sub`, `iss`, `groups`)
- Token validity: `iat`, `exp`, time remaining

**Inputs:** `IDToken` from context
**Outputs to context:** `TokenHeader`, `TokenClaims`

**Note:** This step does not verify the JWT signature. FlashBlade performs signature verification using the IdP's JWKS endpoint. This step is purely for visibility.

### Step 3: STSAssume

**Purpose:** Call `AssumeRoleWithWebIdentity` on the FlashBlade STS VIP to obtain temporary S3 credentials.

**Process:**
1. Build the STS request with query parameters:
   - `Action=AssumeRoleWithWebIdentity`
   - `Version=2011-06-15`
   - `RoleArn=<configured role ARN>`
   - `RoleSessionName=fbsts-validate-<timestamp>`
   - `WebIdentityToken=<ID token>`
   - `DurationSeconds=<configured or default 3600>`
2. POST to the FlashBlade STS VIP endpoint (HTTPS)
3. Parse the XML response

**Displayed data:**
- Full request parameters (WebIdentityToken value truncated)
- STS endpoint URL
- HTTP response status code
- Parsed response: `AccessKeyId` (shown), `SecretAccessKey` (masked), `SessionToken` (truncated -- first 20 + last 6 chars), `Expiration`, `AssumedRoleUser.Arn`, `AssumedRoleUser.AssumedRoleId`
- Step timing

**Inputs:** `IDToken` from context, STS endpoint, role ARN, duration (from config)
**Outputs to context:** `AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration`, `AssumedRoleARN`

### Step 4: S3Validate

**Purpose:** Validate the temporary credentials work for S3 operations against the FlashBlade Data VIP.

**Process (CRUD cycle):**
1. `ListBuckets` -- confirm basic credential validity
2. `PutObject` -- write a small test object (`fbsts-validate/<timestamp>.txt`) with known content
3. `GetObject` -- read it back, verify content matches via SHA-256 hash
4. `DeleteObject` -- clean up the test object

Each operation uses raw HTTP requests signed with SigV4, including the `x-amz-security-token` header for session credentials.

**Displayed data:**
- Data VIP endpoint URL
- Per-operation: operation name, bucket, key, HTTP status, content hash (for PUT/GET), pass/fail, timing
- Overall CRUD result summary

**Inputs:** `AccessKeyId`, `SecretAccessKey`, `SessionToken` from context; Data VIP, bucket name (from config)
**Outputs to context:** `S3Results`

## Configuration

### TOML Config File

Resolution order: CLI flag > local `./.fbsts.toml` > home `~/.fbsts.toml` > interactive prompt.

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

[s3]
test_bucket = "validation-test"
test_key_prefix = "fbsts-validate/"

[tls]
insecure = false
ca_cert = ""
```

### CLI Flags

```
Okta:
  --okta-url        Okta tenant URL
  --client-id       Okta application client ID
  --scopes          OIDC scopes (comma-separated, default: openid,profile,groups)

FlashBlade:
  --sts-endpoint    FlashBlade STS VIP URL
  --data-endpoint   FlashBlade Data VIP URL
  --role-arn        Role ARN to assume
  --account         Object store account name

S3:
  --bucket          Test bucket name
  --key-prefix      Test object key prefix (default: fbsts-validate/)

TLS:
  --insecure        Skip TLS certificate verification
  --ca-cert         Path to custom CA certificate PEM file

Behavior:
  --continue-on-error  Continue through all steps even if one fails
  --token              Skip Okta auth, use a pre-supplied JWT
  --duration           STS session duration in seconds (default: 3600)
  --config             Explicit config file path
```

### Interactive Prompts

When a required value (`okta.tenant_url`, `okta.client_id`, `flashblade.sts_endpoint`, `flashblade.data_endpoint`, `flashblade.role_arn`, `s3.test_bucket`) is missing after checking flags and config files, the tool prompts the user with a description and example:

```
Okta tenant URL (e.g., https://myorg.okta.com): _
```

### Commands

```
fbsts validate [flags]    # Run the full STS validation flow
fbsts init                # Generate a sample .fbsts.toml in the current directory
fbsts version             # Print version information
```

## Output & Rendering

### PanelRenderer (v1)

Uses `charmbracelet/lipgloss` for styled terminal panels. Each step gets a bordered panel with:
- Step name and status indicator (spinner while running, checkmark on success, X on failure)
- Key-value fields with labels, aligned and syntax-highlighted
- Sub-step status lines (for S3 CRUD operations)
- Timing in the panel footer

### Masking Strategy

| Tier | Treatment | Examples |
|------|-----------|----------|
| **Shown in full** | Displayed as-is | AccessKeyId, decoded JWT claims, role ARN, endpoints, HTTP status codes, error messages, request parameters, bucket names, object keys, content hashes |
| **Truncated** | Partial display | Raw JWT: `eyJhbGci...<masked>...kF9xQ`, SessionToken: first 20 + `...` + last 6 chars |
| **Fully masked** | `**********` | SecretAccessKey, any password fields |

### Future: SubwayRenderer

The `Renderer` interface is designed so a `SubwayRenderer` can be added later without modifying any step code. This renderer would display the flow as a subway/metro map with each step as a station, filling in details as the flow progresses. The same `StepResult` data drives both renderers.

## Error Handling

### Behavior

- **Default (fail fast):** Stop at the first step failure, render a full error panel, exit with non-zero code
- **`--continue-on-error`:** Run all steps, mark failures, render a pass/fail summary at the end

### Error Panel Contents

- Step name and phase where the failure occurred
- HTTP status code and raw response body (when applicable)
- Parsed error code
- Human-readable diagnostic hint

### Diagnostic Hints

| Error | Hint |
|-------|------|
| Okta `invalid_client` | Check that client_id is correct and the app is configured for device code grant in Okta |
| Okta `authorization_pending` timeout | User did not complete browser authorization within the timeout window |
| STS `AccessDenied` | Check that the role's trust policy includes your OIDC provider and the aud/sub claims match |
| STS `InvalidIdentityToken` | Token may be expired or the FlashBlade cannot reach the Okta JWKS endpoint to validate signatures |
| STS `MalformedPolicyDocument` | The role's trust policy syntax is invalid -- check conditions and principal format |
| S3 `403 Forbidden` | Temporary credentials are valid but the role's access policy doesn't grant this S3 operation |
| TLS certificate error | FlashBlade is using a self-signed or untrusted certificate. Retry with --insecure or provide --ca-cert |

Additional hints can be added incrementally as common failure modes are discovered.

### TLS Handling

- `--insecure`: skips all certificate verification; prints a visible warning banner at the top of the run
- `--ca-cert /path/to/ca.pem`: adds a custom CA to the Go TLS trust pool
- Both flags apply to all HTTPS connections (STS VIP, Data VIP, Okta endpoints)
- The active TLS mode is displayed in the run header

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All steps passed |
| `1` | A step failed |
| `2` | Configuration error (missing required values, bad TOML, unreachable endpoint) |

## Project Structure

```
fbsts/
├── cmd/
│   └── fbsts/
│       └── main.go              # cobra root + validate/init/version subcommands
├── internal/
│   ├── config/
│   │   ├── config.go            # TOML loading, flag merging, interactive prompts
│   │   └── tls.go               # TLS transport setup (insecure, ca-cert)
│   ├── steps/
│   │   ├── step.go              # Step interface, FlowContext, StepResult types
│   │   ├── okta_device_auth.go  # Step 1: Okta device code flow
│   │   ├── token_decode.go      # Step 2: JWT decode + claims display
│   │   ├── sts_assume.go        # Step 3: AssumeRoleWithWebIdentity
│   │   └── s3_validate.go       # Step 4: S3 CRUD cycle
│   ├── runner/
│   │   └── runner.go            # Pipeline orchestrator, continue-on-error logic
│   ├── render/
│   │   ├── renderer.go          # Renderer interface definition
│   │   ├── panel.go             # PanelRenderer implementation (lipgloss)
│   │   └── mask.go              # Secret masking utilities (truncate, full mask)
│   └── s3signer/
│       └── sigv4.go             # AWS Signature V4 request signing with session token
├── .fbsts.toml.example          # Sample configuration file
├── go.mod
└── go.sum
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/spf13/cobra` | latest | CLI framework and subcommands |
| `github.com/BurntSushi/toml` | latest | TOML config file parsing |
| `github.com/charmbracelet/lipgloss` | latest | Styled terminal panels, boxes, colors |
| `github.com/charmbracelet/log` | latest | Styled log output (warnings, TLS banner) |
| Go standard library | 1.22+ | `net/http`, `crypto/tls`, `crypto/hmac`, `crypto/sha256`, `encoding/xml`, `encoding/json`, `encoding/base64` |

No AWS SDK is used in v1. STS and S3 calls use raw HTTP with hand-rolled SigV4 signing. This gives full visibility into every header and parameter for diagnostic display. The architecture does not preclude adding `aws-sdk-go-v2` later -- new steps can use the SDK internally while existing steps continue using raw HTTP.

## Reference Code

The existing project at `rp-pure-utils/go_create_s3_objects` contains patterns to reference (not import directly):
- **TLS setup** (`main.go:450-501`): `http.Client` with `InsecureSkipVerify` and custom transport config
- **`parseSize` / `formatSize`** (`main.go:188-251`): human-readable size formatting utilities
- **`ErrorTracker`** (`main.go:74-112`): thread-safe error aggregation pattern

## FlashBlade STS Reference

- FlashBlade calls this feature "Object Identity Federation"
- STS VIP is a separate network interface from the Data VIP (service type `sts`)
- Uses AWS STS Query API Version `2011-06-15`
- Only `AssumeRoleWithWebIdentity` and `AssumeRoleWithSAML` are supported (no plain `AssumeRole`)
- FlashBlade supports up to 5 OIDC providers and 5 SAML providers
- Temporary credentials are array-local (cannot be used across different FlashBlade arrays)
- Troubleshooting: search `http.log` on the FlashBlade for operation names
- Official docs: [Quick Start Guide: Object Identity Federation](https://support.purestorage.com/bundle/m_flashblade_object_services/page/FlashBlade/Purity_FB/FlashBlade_Object_Services/topics/c_quick_start_guide_object_identity_federation_on_flashblade.html)
