# FlashBlade STS Validator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Go CLI tool (`fbsts`) that validates the complete AssumeRoleWithWebIdentity flow from Okta OIDC through FlashBlade STS to S3, with rich visual output.

**Architecture:** Pipeline of 4 steps (OktaDeviceAuth, TokenDecode, STSAssume, S3Validate) executed by a Runner, each producing StepResults consumed by a pluggable Renderer. Config loaded from TOML with CLI flag overrides and interactive fallback prompts.

**Tech Stack:** Go 1.22+, cobra (CLI), BurntSushi/toml (config), charmbracelet/lipgloss (rendering), stdlib (net/http, crypto/*, encoding/*)

**Spec:** `docs/superpowers/specs/2026-04-14-fbsts-validator-design.md`

---

## File Map

```
cmd/fbsts/main.go                   — cobra root, validate/init/version subcommands, flag binding
internal/config/config.go           — Config struct, TOML loading, resolution, interactive prompts
internal/config/config_test.go      — config loading and merging tests
internal/config/tls.go              — NewHTTPClient with insecure/ca-cert support
internal/config/tls_test.go         — TLS client tests
internal/steps/step.go              — Step interface, FlowContext, StepResult, Field, SubStep types
internal/steps/step_test.go         — FlowContext tests
internal/steps/okta_device_auth.go  — Step 1: Okta device code flow
internal/steps/okta_device_auth_test.go
internal/steps/token_decode.go      — Step 2: JWT header/claims decode
internal/steps/token_decode_test.go
internal/steps/sts_assume.go        — Step 3: AssumeRoleWithWebIdentity call
internal/steps/sts_assume_test.go
internal/steps/s3_validate.go       — Step 4: S3 CRUD cycle
internal/steps/s3_validate_test.go
internal/runner/runner.go           — pipeline orchestrator, continue-on-error
internal/runner/runner_test.go
internal/render/renderer.go         — Renderer interface
internal/render/mask.go             — MaskSecret, TruncateJWT, TruncateToken
internal/render/mask_test.go
internal/render/panel.go            — PanelRenderer (lipgloss)
internal/render/panel_test.go
internal/s3signer/sigv4.go          — SigV4 request signing with session token
internal/s3signer/sigv4_test.go
.fbsts.toml.example                 — sample config file
.gitignore                          — binaries, .superpowers/
```

---

### Task 1: Project Scaffolding

**Files:**
- Create: `go.mod`, `.gitignore`, directory structure

- [ ] **Step 1: Initialize Go module and directories**

```bash
cd /Users/rpope/Projects/github.com/pure-experimental/rp-fbstsvalidator
go mod init github.com/pure-experimental/rp-fbstsvalidator
mkdir -p cmd/fbsts internal/config internal/steps internal/runner internal/render internal/s3signer
```

- [ ] **Step 2: Create .gitignore**

Create `.gitignore`:

```gitignore
# Binaries
fbsts
*.exe

# Brainstorm artifacts
.superpowers/

# IDE
.idea/
.vscode/
*.swp

# OS
.DS_Store
```

- [ ] **Step 3: Install dependencies**

```bash
go get github.com/spf13/cobra@latest
go get github.com/BurntSushi/toml@latest
go get github.com/charmbracelet/lipgloss@latest
go get github.com/charmbracelet/log@latest
```

- [ ] **Step 4: Create minimal main.go to verify build**

Create `cmd/fbsts/main.go`:

```go
package main

import "fmt"

func main() {
	fmt.Println("fbsts")
}
```

- [ ] **Step 5: Verify build**

Run: `go build -o fbsts ./cmd/fbsts && ./fbsts`
Expected: prints `fbsts`

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum .gitignore cmd/ internal/ 
git commit -m "Initialize project scaffolding"
```

---

### Task 2: Core Types

**Files:**
- Create: `internal/steps/step.go`
- Test: `internal/steps/step_test.go`

- [ ] **Step 1: Write tests for core types**

Create `internal/steps/step_test.go`:

```go
package steps

import (
	"net/http"
	"testing"
	"time"
)

func TestFlowContextInitialization(t *testing.T) {
	cfg := &Config{}
	client := &http.Client{}
	ctx := NewFlowContext(cfg, client)

	if ctx.Config != cfg {
		t.Error("Config not set")
	}
	if ctx.HTTPClient != client {
		t.Error("HTTPClient not set")
	}
	if ctx.IDToken != "" {
		t.Error("IDToken should be empty")
	}
}

func TestFieldCreation(t *testing.T) {
	f := Field{Label: "AccessKeyId", Value: "AKIA1234", Sensitive: false}
	if f.Label != "AccessKeyId" {
		t.Errorf("expected AccessKeyId, got %s", f.Label)
	}
	if f.Sensitive {
		t.Error("AccessKeyId should not be sensitive")
	}

	secret := Field{Label: "SecretAccessKey", Value: "wJalr...", Sensitive: true}
	if !secret.Sensitive {
		t.Error("SecretAccessKey should be sensitive")
	}
}

func TestStepResultWithSubSteps(t *testing.T) {
	result := &StepResult{
		Title: "S3 Validate",
		Fields: []Field{
			{Label: "Endpoint", Value: "https://fb-data.example.com"},
		},
		SubSteps: []SubStep{
			{Name: "ListBuckets", Status: StatusPass, Duration: 50 * time.Millisecond},
			{Name: "PutObject", Status: StatusFail, Duration: 120 * time.Millisecond, Error: "403 Forbidden"},
		},
		Duration: 170 * time.Millisecond,
	}

	if len(result.SubSteps) != 2 {
		t.Errorf("expected 2 substeps, got %d", len(result.SubSteps))
	}
	if result.SubSteps[0].Status != StatusPass {
		t.Error("ListBuckets should pass")
	}
	if result.SubSteps[1].Status != StatusFail {
		t.Error("PutObject should fail")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/steps/ -v`
Expected: compilation errors — types not defined

- [ ] **Step 3: Implement core types**

Create `internal/steps/step.go`:

```go
package steps

import (
	"net/http"
	"time"
)

// Status represents the outcome of a step or sub-step.
type Status int

const (
	StatusPending Status = iota
	StatusPass
	StatusFail
)

// Config holds all tool configuration. Populated by the config package
// and passed to steps via FlowContext.
type Config struct {
	// Okta
	OktaTenantURL string
	OktaClientID  string
	OktaScopes    []string

	// FlashBlade
	STSEndpoint  string
	DataEndpoint string
	RoleARN      string
	Account      string

	// S3
	TestBucket    string
	TestKeyPrefix string

	// TLS
	Insecure bool
	CACert   string

	// Behavior
	ContinueOnError bool
	PreSuppliedToken string
	Duration         int
}

// FlowContext carries state between pipeline steps.
type FlowContext struct {
	Config     *Config
	HTTPClient *http.Client

	// Set by OktaDeviceAuth
	IDToken     string
	AccessToken string

	// Set by TokenDecode
	TokenHeader map[string]interface{}
	TokenClaims map[string]interface{}

	// Set by STSAssume
	AccessKeyId    string
	SecretAccessKey string
	SessionToken   string
	Expiration     time.Time
	AssumedRoleARN string

	// Set by S3Validate
	S3Results []S3OpResult
}

// NewFlowContext creates a FlowContext with the given config and HTTP client.
func NewFlowContext(cfg *Config, client *http.Client) *FlowContext {
	return &FlowContext{
		Config:     cfg,
		HTTPClient: client,
	}
}

// Field is a labeled value for display by the renderer.
type Field struct {
	Label     string
	Value     string
	Sensitive bool // true = renderer should mask this value
}

// SubStep represents a nested operation within a step (e.g., individual S3 ops).
type SubStep struct {
	Name     string
	Status   Status
	Duration time.Duration
	Error    string
	Fields   []Field
}

// StepResult is the structured output of a step, consumed by the renderer.
type StepResult struct {
	Title    string
	Fields   []Field
	SubSteps []SubStep
	Duration time.Duration
}

// S3OpResult records the outcome of a single S3 operation.
type S3OpResult struct {
	Operation  string
	Bucket     string
	Key        string
	HTTPStatus int
	Pass       bool
	Duration   time.Duration
	Error      string
}

// Step is the interface each pipeline phase implements.
type Step interface {
	Name() string
	Execute(ctx *FlowContext) (*StepResult, error)
}

// StepError wraps an error with a diagnostic hint for the renderer.
type StepError struct {
	Err  error
	Hint string
	Code string // parsed error code (e.g., "AccessDenied")
	HTTPStatus int
	RawResponse string
}

func (e *StepError) Error() string {
	return e.Err.Error()
}

func (e *StepError) Unwrap() error {
	return e.Err
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/steps/ -v`
Expected: all 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/steps/step.go internal/steps/step_test.go
git commit -m "Add core types: Step interface, FlowContext, StepResult"
```

---

### Task 3: Masking Utilities

**Files:**
- Create: `internal/render/mask.go`
- Test: `internal/render/mask_test.go`

- [ ] **Step 1: Write tests for masking functions**

Create `internal/render/mask_test.go`:

```go
package render

import "testing"

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "**********"},
		{"short", "**********"},
		{"", "**********"},
	}
	for _, tt := range tests {
		got := MaskSecret(tt.input)
		if got != tt.expected {
			t.Errorf("MaskSecret(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestTruncateJWT(t *testing.T) {
	// A fake JWT with three dot-separated parts
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Signature_Bytes_Here"
	result := TruncateJWT(jwt)

	// Should contain the header, a masked middle, and a signature hint
	if len(result) >= len(jwt) {
		t.Errorf("TruncateJWT should shorten the token, got len %d vs original %d", len(result), len(jwt))
	}
	if result[:10] != jwt[:10] {
		t.Error("TruncateJWT should preserve the start of the header")
	}
	if !contains(result, "<masked>") {
		t.Error("TruncateJWT should contain <masked> placeholder")
	}
}

func TestTruncateJWTInvalid(t *testing.T) {
	// Not a valid JWT (no dots)
	result := TruncateJWT("not-a-jwt")
	if result != "not-a-jwt" {
		t.Errorf("TruncateJWT should return non-JWTs unchanged, got %q", result)
	}
}

func TestTruncateToken(t *testing.T) {
	token := "FwoGZXIvYXdzEBYaDHQqX0123456789abcdef0123456789abcdef"
	result := TruncateToken(token, 20, 6)

	if len(result) >= len(token) {
		t.Errorf("TruncateToken should shorten the token")
	}
	// First 20 chars preserved
	if result[:20] != token[:20] {
		t.Error("TruncateToken should preserve prefix")
	}
	// Last 6 chars preserved
	if result[len(result)-6:] != token[len(token)-6:] {
		t.Error("TruncateToken should preserve suffix")
	}
	if !contains(result, "...") {
		t.Error("TruncateToken should contain ellipsis")
	}
}

func TestTruncateTokenShort(t *testing.T) {
	// Token shorter than prefix+suffix — return unchanged
	result := TruncateToken("short", 20, 6)
	if result != "short" {
		t.Errorf("TruncateToken should return short tokens unchanged, got %q", result)
	}
}

func TestMaskField(t *testing.T) {
	// Non-sensitive field returned as-is
	val := MaskField("AKIAIOSFODNN7EXAMPLE", false)
	if val != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("non-sensitive field should be unchanged, got %q", val)
	}

	// Sensitive field masked
	val = MaskField("wJalrXUtnFEMI", true)
	if val != "**********" {
		t.Errorf("sensitive field should be masked, got %q", val)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/render/ -v`
Expected: compilation errors — functions not defined

- [ ] **Step 3: Implement masking functions**

Create `internal/render/mask.go`:

```go
package render

import "strings"

// MaskSecret replaces any value with asterisks. Used for SecretAccessKey, passwords.
func MaskSecret(value string) string {
	return "**********"
}

// TruncateJWT shows the header portion, masks the payload, and shows a signature hint.
// Input format: header.payload.signature
// Output format: eyJhbGci...<masked>...kF9xQ
func TruncateJWT(jwt string) string {
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		return jwt
	}

	header := parts[0]
	sig := parts[2]

	// Show first 10 chars of header, last 5 of signature
	headerHint := header
	if len(header) > 10 {
		headerHint = header[:10]
	}
	sigHint := sig
	if len(sig) > 5 {
		sigHint = sig[len(sig)-5:]
	}

	return headerHint + "...<masked>..." + sigHint
}

// TruncateToken shows the first `prefix` and last `suffix` characters with an ellipsis in between.
// If the token is shorter than prefix+suffix+3, it is returned unchanged.
func TruncateToken(token string, prefix, suffix int) string {
	if len(token) <= prefix+suffix+3 {
		return token
	}
	return token[:prefix] + "..." + token[len(token)-suffix:]
}

// MaskField returns the value masked or unchanged based on the sensitive flag.
func MaskField(value string, sensitive bool) string {
	if sensitive {
		return MaskSecret(value)
	}
	return value
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/render/ -v`
Expected: all 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/render/mask.go internal/render/mask_test.go
git commit -m "Add secret masking utilities"
```

---

### Task 4: Renderer Interface and PanelRenderer

**Files:**
- Create: `internal/render/renderer.go`, `internal/render/panel.go`
- Test: `internal/render/panel_test.go`

- [ ] **Step 1: Write the renderer interface**

Create `internal/render/renderer.go`:

```go
package render

import "github.com/pure-experimental/rp-fbstsvalidator/internal/steps"

// Renderer handles all terminal output for the validation flow.
type Renderer interface {
	RenderStepStart(name string)
	RenderStepResult(name string, result *steps.StepResult)
	RenderStepError(name string, err error)
	RenderSummary(results map[string]*steps.StepResult, order []string)
	RenderWarning(msg string)
}
```

- [ ] **Step 2: Write tests for PanelRenderer**

Create `internal/render/panel_test.go`:

```go
package render

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

func TestPanelRendererStepStart(t *testing.T) {
	var buf bytes.Buffer
	r := NewPanelRenderer(&buf)
	r.RenderStepStart("OktaDeviceAuth")

	output := buf.String()
	if !strings.Contains(output, "OktaDeviceAuth") {
		t.Errorf("RenderStepStart should contain step name, got: %s", output)
	}
}

func TestPanelRendererStepResult(t *testing.T) {
	var buf bytes.Buffer
	r := NewPanelRenderer(&buf)

	result := &steps.StepResult{
		Title: "Token Decode",
		Fields: []steps.Field{
			{Label: "Algorithm", Value: "RS256", Sensitive: false},
			{Label: "SecretKey", Value: "supersecret", Sensitive: true},
		},
		Duration: 42 * time.Millisecond,
	}
	r.RenderStepResult("TokenDecode", result)

	output := buf.String()
	if !strings.Contains(output, "RS256") {
		t.Error("should display non-sensitive value RS256")
	}
	if strings.Contains(output, "supersecret") {
		t.Error("should NOT display sensitive value in clear text")
	}
	if !strings.Contains(output, "**********") {
		t.Error("should mask sensitive value")
	}
}

func TestPanelRendererStepResultWithSubSteps(t *testing.T) {
	var buf bytes.Buffer
	r := NewPanelRenderer(&buf)

	result := &steps.StepResult{
		Title: "S3 Validate",
		SubSteps: []steps.SubStep{
			{Name: "ListBuckets", Status: steps.StatusPass, Duration: 30 * time.Millisecond},
			{Name: "PutObject", Status: steps.StatusFail, Duration: 100 * time.Millisecond, Error: "403 Forbidden"},
		},
		Duration: 130 * time.Millisecond,
	}
	r.RenderStepResult("S3Validate", result)

	output := buf.String()
	if !strings.Contains(output, "ListBuckets") {
		t.Error("should display sub-step name ListBuckets")
	}
	if !strings.Contains(output, "PutObject") {
		t.Error("should display sub-step name PutObject")
	}
}

func TestPanelRendererError(t *testing.T) {
	var buf bytes.Buffer
	r := NewPanelRenderer(&buf)

	err := &steps.StepError{
		Err:         fmt.Errorf("access denied"),
		Hint:        "Check that the role trust policy includes your OIDC provider",
		Code:        "AccessDenied",
		HTTPStatus:  403,
		RawResponse: "<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>",
	}
	r.RenderStepError("STSAssume", err)

	output := buf.String()
	if !strings.Contains(output, "AccessDenied") {
		t.Error("should display error code")
	}
	if !strings.Contains(output, "trust policy") {
		t.Error("should display diagnostic hint")
	}
}

func TestPanelRendererSummary(t *testing.T) {
	var buf bytes.Buffer
	r := NewPanelRenderer(&buf)

	results := map[string]*steps.StepResult{
		"OktaDeviceAuth": {Title: "Okta Device Auth", Duration: 5 * time.Second},
		"TokenDecode":    {Title: "Token Decode", Duration: 2 * time.Millisecond},
		"STSAssume":      {Title: "STS Assume", Duration: 200 * time.Millisecond},
	}
	order := []string{"OktaDeviceAuth", "TokenDecode", "STSAssume"}
	r.RenderSummary(results, order)

	output := buf.String()
	if !strings.Contains(output, "Okta Device Auth") {
		t.Error("summary should list step names")
	}
}

func TestPanelRendererWarning(t *testing.T) {
	var buf bytes.Buffer
	r := NewPanelRenderer(&buf)
	r.RenderWarning("TLS verification disabled (--insecure)")

	output := buf.String()
	if !strings.Contains(output, "TLS verification disabled") {
		t.Error("should display warning text")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/render/ -v`
Expected: compilation errors — `NewPanelRenderer` not defined

- [ ] **Step 4: Implement PanelRenderer**

Create `internal/render/panel.go`:

```go
package render

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12"))

	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")).
			Width(22)

	valueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15"))

	passStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10")).
			Bold(true)

	failStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")).
			Bold(true)

	warnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("11")).
			Bold(true)

	hintStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("14")).
			Italic(true)

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("8")).
			Padding(1, 2)

	errorBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("9")).
				Padding(1, 2)

	summaryBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.DoubleBorder()).
				BorderForeground(lipgloss.Color("12")).
				Padding(1, 2)
)

// PanelRenderer displays step results as bordered lipgloss panels.
type PanelRenderer struct {
	out io.Writer
}

// NewPanelRenderer creates a PanelRenderer writing to the given writer.
func NewPanelRenderer(out io.Writer) *PanelRenderer {
	return &PanelRenderer{out: out}
}

func (r *PanelRenderer) RenderStepStart(name string) {
	spinner := warnStyle.Render("●")
	title := titleStyle.Render(name)
	fmt.Fprintf(r.out, "\n%s %s running...\n", spinner, title)
}

func (r *PanelRenderer) RenderStepResult(name string, result *steps.StepResult) {
	var content strings.Builder

	check := passStyle.Render("✓")
	title := titleStyle.Render(result.Title)
	content.WriteString(fmt.Sprintf("%s %s\n\n", check, title))

	// Render fields
	for _, f := range result.Fields {
		label := labelStyle.Render(f.Label + ":")
		val := MaskField(f.Value, f.Sensitive)
		value := valueStyle.Render(val)
		content.WriteString(fmt.Sprintf("  %s %s\n", label, value))
	}

	// Render sub-steps
	if len(result.SubSteps) > 0 {
		content.WriteString("\n")
		for _, ss := range result.SubSteps {
			var icon string
			var nameStyled string
			if ss.Status == steps.StatusPass {
				icon = passStyle.Render("✓")
				nameStyled = passStyle.Render(ss.Name)
			} else {
				icon = failStyle.Render("✗")
				nameStyled = failStyle.Render(ss.Name)
			}
			dur := lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(fmt.Sprintf("(%s)", ss.Duration.Round(time.Millisecond)))
			content.WriteString(fmt.Sprintf("  %s %s %s", icon, nameStyled, dur))
			if ss.Error != "" {
				content.WriteString(fmt.Sprintf(" — %s", ss.Error))
			}
			content.WriteString("\n")

			// Sub-step fields
			for _, f := range ss.Fields {
				label := labelStyle.Render("    " + f.Label + ":")
				val := MaskField(f.Value, f.Sensitive)
				value := valueStyle.Render(val)
				content.WriteString(fmt.Sprintf("  %s %s\n", label, value))
			}
		}
	}

	// Duration footer
	dur := lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(
		fmt.Sprintf("completed in %s", result.Duration.Round(time.Millisecond)))
	content.WriteString(fmt.Sprintf("\n  %s", dur))

	panel := borderStyle.Render(content.String())
	fmt.Fprintln(r.out, panel)
}

func (r *PanelRenderer) RenderStepError(name string, err error) {
	var content strings.Builder

	x := failStyle.Render("✗")
	title := titleStyle.Render(name + " — FAILED")
	content.WriteString(fmt.Sprintf("%s %s\n\n", x, title))

	// If it's a StepError, show structured diagnostics
	if se, ok := err.(*steps.StepError); ok {
		if se.Code != "" {
			content.WriteString(fmt.Sprintf("  %s %s\n", labelStyle.Render("Error Code:"), failStyle.Render(se.Code)))
		}
		if se.HTTPStatus != 0 {
			content.WriteString(fmt.Sprintf("  %s %s\n", labelStyle.Render("HTTP Status:"), valueStyle.Render(fmt.Sprintf("%d", se.HTTPStatus))))
		}
		content.WriteString(fmt.Sprintf("  %s %s\n", labelStyle.Render("Error:"), valueStyle.Render(se.Err.Error())))
		if se.RawResponse != "" {
			content.WriteString(fmt.Sprintf("\n  %s\n  %s\n", labelStyle.Render("Raw Response:"), valueStyle.Render(se.RawResponse)))
		}
		if se.Hint != "" {
			content.WriteString(fmt.Sprintf("\n  %s %s\n", warnStyle.Render("Hint:"), hintStyle.Render(se.Hint)))
		}
	} else {
		content.WriteString(fmt.Sprintf("  %s %s\n", labelStyle.Render("Error:"), valueStyle.Render(err.Error())))
	}

	panel := errorBorderStyle.Render(content.String())
	fmt.Fprintln(r.out, panel)
}

func (r *PanelRenderer) RenderSummary(results map[string]*steps.StepResult, order []string) {
	var content strings.Builder

	title := titleStyle.Render("Validation Summary")
	content.WriteString(fmt.Sprintf("%s\n\n", title))

	var totalDuration time.Duration
	for _, name := range order {
		result, ok := results[name]
		if !ok {
			x := failStyle.Render("✗")
			content.WriteString(fmt.Sprintf("  %s %s — skipped or failed\n", x, name))
			continue
		}
		check := passStyle.Render("✓")
		dur := lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(
			fmt.Sprintf("(%s)", result.Duration.Round(time.Millisecond)))
		content.WriteString(fmt.Sprintf("  %s %s %s\n", check, result.Title, dur))
		totalDuration += result.Duration
	}

	content.WriteString(fmt.Sprintf("\n  Total: %s", totalDuration.Round(time.Millisecond)))

	panel := summaryBorderStyle.Render(content.String())
	fmt.Fprintln(r.out, panel)
}

func (r *PanelRenderer) RenderWarning(msg string) {
	banner := warnStyle.Render("⚠ WARNING: " + msg)
	panel := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("11")).
		Padding(0, 2).
		Render(banner)
	fmt.Fprintln(r.out, panel)
}
```

- [ ] **Step 5: Add missing import to test file**

Add `"fmt"` to the imports in `internal/render/panel_test.go` (needed for `fmt.Errorf` in the error test).

- [ ] **Step 6: Run tests**

Run: `go test ./internal/render/ -v`
Expected: all tests PASS

- [ ] **Step 7: Commit**

```bash
git add internal/render/renderer.go internal/render/panel.go internal/render/panel_test.go
git commit -m "Add Renderer interface and PanelRenderer with lipgloss"
```

---

### Task 5: Config Loading

**Files:**
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write config tests**

Create `internal/config/config_test.go`:

```go
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
	// Create a home config
	homeDir := t.TempDir()
	homeCfg := filepath.Join(homeDir, ".fbsts.toml")
	os.WriteFile(homeCfg, []byte(`
[okta]
tenant_url = "https://home.okta.com"
client_id = "home-client"
`), 0644)

	// Create a local config that overrides tenant_url
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

	// Local overrides home
	if cfg.OktaTenantURL != "https://local.okta.com" {
		t.Errorf("OktaTenantURL = %q, want local override", cfg.OktaTenantURL)
	}
	// Home value preserved where local doesn't set it
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -v`
Expected: compilation errors

- [ ] **Step 3: Implement config loading**

Create `internal/config/config.go`:

```go
package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

// TOMLConfig mirrors the TOML file structure.
type TOMLConfig struct {
	Okta      OktaConfig      `toml:"okta"`
	FlashBlade FlashBladeConfig `toml:"flashblade"`
	S3        S3Config         `toml:"s3"`
	TLS       TLSConfig        `toml:"tls"`
}

type OktaConfig struct {
	TenantURL string   `toml:"tenant_url"`
	ClientID  string   `toml:"client_id"`
	Scopes    []string `toml:"scopes"`
}

type FlashBladeConfig struct {
	STSEndpoint  string `toml:"sts_endpoint"`
	DataEndpoint string `toml:"data_endpoint"`
	RoleARN      string `toml:"role_arn"`
	Account      string `toml:"account"`
}

type S3Config struct {
	TestBucket    string `toml:"test_bucket"`
	TestKeyPrefix string `toml:"test_key_prefix"`
}

type TLSConfig struct {
	Insecure bool   `toml:"insecure"`
	CACert   string `toml:"ca_cert"`
}

// FlagOverrides holds values from CLI flags. Empty strings mean "not set".
type FlagOverrides struct {
	OktaURL     string
	ClientID    string
	Scopes      string
	STSEndpoint string
	DataEndpoint string
	RoleARN     string
	Account     string
	Bucket      string
	KeyPrefix   string
	Insecure    bool
	InsecureSet bool // true if --insecure was explicitly passed
	CACert      string
	Token       string
	Duration    int
	ContinueOnError bool
}

// LoadFromFile reads and parses a single TOML config file.
func LoadFromFile(path string) (*TOMLConfig, error) {
	cfg := &TOMLConfig{}
	_, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("loading config from %s: %w", path, err)
	}
	return cfg, nil
}

// ResolveConfig loads config by merging home → local → explicit file.
// Empty paths are skipped. Explicit file takes precedence over all.
func ResolveConfig(homePath, localPath, explicitPath string) (*TOMLConfig, error) {
	base := &TOMLConfig{}

	if explicitPath != "" {
		return LoadFromFile(explicitPath)
	}

	// Load home config first (lower priority)
	if homePath != "" {
		if _, err := os.Stat(homePath); err == nil {
			home, err := LoadFromFile(homePath)
			if err != nil {
				return nil, err
			}
			mergeConfig(base, home)
		}
	}

	// Load local config (higher priority)
	if localPath != "" {
		if _, err := os.Stat(localPath); err == nil {
			local, err := LoadFromFile(localPath)
			if err != nil {
				return nil, err
			}
			mergeConfig(base, local)
		}
	}

	return base, nil
}

// mergeConfig applies non-empty values from src onto dst.
func mergeConfig(dst, src *TOMLConfig) {
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
		dst.TLS.Insecure = true
	}
	if src.TLS.CACert != "" {
		dst.TLS.CACert = src.TLS.CACert
	}
}

// ApplyOverrides applies CLI flag values onto a TOMLConfig.
func ApplyOverrides(cfg *TOMLConfig, flags *FlagOverrides) {
	if flags.OktaURL != "" {
		cfg.Okta.TenantURL = flags.OktaURL
	}
	if flags.ClientID != "" {
		cfg.Okta.ClientID = flags.ClientID
	}
	if flags.Scopes != "" {
		cfg.Okta.Scopes = strings.Split(flags.Scopes, ",")
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
	if flags.InsecureSet {
		cfg.TLS.Insecure = flags.Insecure
	}
	if flags.CACert != "" {
		cfg.TLS.CACert = flags.CACert
	}
}

// ToStepsConfig converts a TOMLConfig to the steps.Config used by the pipeline.
func (c *TOMLConfig) ToStepsConfig() *steps.Config {
	scopes := c.Okta.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "groups"}
	}

	keyPrefix := c.S3.TestKeyPrefix
	if keyPrefix == "" {
		keyPrefix = "fbsts-validate/"
	}

	duration := 3600

	return &steps.Config{
		OktaTenantURL: c.Okta.TenantURL,
		OktaClientID:  c.Okta.ClientID,
		OktaScopes:    scopes,
		STSEndpoint:   c.FlashBlade.STSEndpoint,
		DataEndpoint:  c.FlashBlade.DataEndpoint,
		RoleARN:       c.FlashBlade.RoleARN,
		Account:       c.FlashBlade.Account,
		TestBucket:    c.S3.TestBucket,
		TestKeyPrefix: keyPrefix,
		Insecure:      c.TLS.Insecure,
		CACert:        c.TLS.CACert,
		Duration:      duration,
	}
}

// PromptMissing asks the user for any required values not yet set.
// It reads from stdin. Returns an error if stdin is not a terminal
// and values are still missing.
func PromptMissing(cfg *TOMLConfig, reader *bufio.Reader) error {
	prompts := []struct {
		value   *string
		name    string
		example string
	}{
		{&cfg.Okta.TenantURL, "Okta tenant URL", "https://myorg.okta.com"},
		{&cfg.Okta.ClientID, "Okta client ID", "0oa1b2c3d4e5f6g7h8i9"},
		{&cfg.FlashBlade.STSEndpoint, "FlashBlade STS endpoint", "https://fb-sts.example.com"},
		{&cfg.FlashBlade.DataEndpoint, "FlashBlade Data endpoint", "https://fb-data.example.com"},
		{&cfg.FlashBlade.RoleARN, "Role ARN", "arn:aws:iam::123456789:role/my-role"},
		{&cfg.S3.TestBucket, "Test bucket name", "validation-test"},
	}

	for _, p := range prompts {
		if *p.value != "" {
			continue
		}
		fmt.Printf("%s (e.g., %s): ", p.name, p.example)
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading %s: %w", p.name, err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return fmt.Errorf("%s is required", p.name)
		}
		*p.value = line
	}

	return nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/config/ -v`
Expected: all 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "Add TOML config loading with resolution and flag overrides"
```

---

### Task 6: TLS Configuration

**Files:**
- Create: `internal/config/tls.go`
- Test: `internal/config/tls_test.go`

- [ ] **Step 1: Write TLS tests**

Create `internal/config/tls_test.go`:

```go
package config

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestNewHTTPClientDefault(t *testing.T) {
	client, err := NewHTTPClient(false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("client should not be nil")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport should be *http.Transport")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false by default")
	}
}

func TestNewHTTPClientInsecure(t *testing.T) {
	client, err := NewHTTPClient(true, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := client.Transport.(*http.Transport)
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true when insecure=true")
	}
}

func TestNewHTTPClientCustomCA(t *testing.T) {
	// Create a minimal PEM file (self-signed test cert)
	// This is just to test that the file is loaded, not that TLS works with it
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")

	// A minimal self-signed cert for testing file loading
	pemData := `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLU3
jSO0xwuSMNMCuMH+KB2IH2GEHGnBPE/gHIEzN7AMKoSH+GHa5MU5UV+IhC/6v3M
/M0bk0YhPOIylJGrI9SjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2wpSek3WKqjG
8rlGXaRSJNoqG7NNjPi4UFSfGjeBkBkCIH5hPlICjGKR3DYaLjFi/MHZ1FsSs/fl
f8GqAaJMFuJh
-----END CERTIFICATE-----`
	os.WriteFile(caPath, []byte(pemData), 0644)

	client, err := NewHTTPClient(false, caPath)
	if err != nil {
		t.Fatalf("unexpected error with custom CA: %v", err)
	}
	if client == nil {
		t.Fatal("client should not be nil")
	}
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("RootCAs should be set when ca_cert is provided")
	}
}

func TestNewHTTPClientBadCAPath(t *testing.T) {
	_, err := NewHTTPClient(false, "/nonexistent/ca.pem")
	if err == nil {
		t.Error("expected error for nonexistent CA file")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -v -run TestNewHTTP`
Expected: compilation errors

- [ ] **Step 3: Implement TLS client factory**

Create `internal/config/tls.go`:

```go
package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// NewHTTPClient builds an *http.Client configured for FlashBlade environments.
// If insecure is true, TLS certificate verification is skipped.
// If caCertPath is non-empty, the PEM file is added to the trust pool.
func NewHTTPClient(insecure bool, caCertPath string) (*http.Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure,
	}

	if caCertPath != "" && !insecure {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("reading CA certificate %s: %w", caCertPath, err)
		}

		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caCertPath)
		}
		tlsConfig.RootCAs = pool
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}, nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/config/ -v`
Expected: all config + TLS tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/config/tls.go internal/config/tls_test.go
git commit -m "Add TLS client factory with insecure and custom CA support"
```

---

### Task 7: Runner

**Files:**
- Create: `internal/runner/runner.go`
- Test: `internal/runner/runner_test.go`

- [ ] **Step 1: Write runner tests with mock steps**

Create `internal/runner/runner_test.go`:

```go
package runner

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/pure-experimental/rp-fbstsvalidator/internal/render"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

// mockStep implements steps.Step for testing.
type mockStep struct {
	name     string
	result   *steps.StepResult
	err      error
	executed bool
}

func (m *mockStep) Name() string { return m.name }
func (m *mockStep) Execute(ctx *steps.FlowContext) (*steps.StepResult, error) {
	m.executed = true
	time.Sleep(1 * time.Millisecond) // simulate work
	return m.result, m.err
}

func TestRunnerAllPass(t *testing.T) {
	var buf bytes.Buffer
	r := New(render.NewPanelRenderer(&buf))

	step1 := &mockStep{name: "Step1", result: &steps.StepResult{Title: "Step 1", Duration: time.Millisecond}}
	step2 := &mockStep{name: "Step2", result: &steps.StepResult{Title: "Step 2", Duration: time.Millisecond}}

	ctx := steps.NewFlowContext(&steps.Config{}, nil)
	err := r.Run(ctx, []steps.Step{step1, step2}, false)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !step1.executed || !step2.executed {
		t.Error("all steps should execute")
	}
}

func TestRunnerFailFast(t *testing.T) {
	var buf bytes.Buffer
	r := New(render.NewPanelRenderer(&buf))

	step1 := &mockStep{name: "Step1", err: errors.New("boom")}
	step2 := &mockStep{name: "Step2", result: &steps.StepResult{Title: "Step 2"}}

	ctx := steps.NewFlowContext(&steps.Config{}, nil)
	err := r.Run(ctx, []steps.Step{step1, step2}, false)

	if err == nil {
		t.Error("expected error from failing step")
	}
	if !step1.executed {
		t.Error("step1 should have executed")
	}
	if step2.executed {
		t.Error("step2 should NOT execute after step1 fails (fail fast)")
	}
}

func TestRunnerContinueOnError(t *testing.T) {
	var buf bytes.Buffer
	r := New(render.NewPanelRenderer(&buf))

	step1 := &mockStep{name: "Step1", err: errors.New("boom")}
	step2 := &mockStep{name: "Step2", result: &steps.StepResult{Title: "Step 2", Duration: time.Millisecond}}

	ctx := steps.NewFlowContext(&steps.Config{}, nil)
	err := r.Run(ctx, []steps.Step{step1, step2}, true)

	if err == nil {
		t.Error("expected error even with continue-on-error")
	}
	if !step1.executed {
		t.Error("step1 should have executed")
	}
	if !step2.executed {
		t.Error("step2 should execute despite step1 failure (continue-on-error)")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/runner/ -v`
Expected: compilation errors

- [ ] **Step 3: Implement runner**

Create `internal/runner/runner.go`:

```go
package runner

import (
	"fmt"
	"time"

	"github.com/pure-experimental/rp-fbstsvalidator/internal/render"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

// Runner orchestrates the step pipeline.
type Runner struct {
	renderer render.Renderer
}

// New creates a Runner with the given renderer.
func New(renderer render.Renderer) *Runner {
	return &Runner{renderer: renderer}
}

// Run executes each step in order. If continueOnError is false, it stops at
// the first failure. Returns an error if any step failed.
func (r *Runner) Run(ctx *steps.FlowContext, pipeline []steps.Step, continueOnError bool) error {
	results := make(map[string]*steps.StepResult)
	var order []string
	var firstErr error

	for _, step := range pipeline {
		name := step.Name()
		order = append(order, name)

		r.renderer.RenderStepStart(name)

		start := time.Now()
		result, err := step.Execute(ctx)
		elapsed := time.Since(start)

		if err != nil {
			r.renderer.RenderStepError(name, err)

			if firstErr == nil {
				firstErr = fmt.Errorf("step %s failed: %w", name, err)
			}

			if !continueOnError {
				return firstErr
			}
			continue
		}

		if result.Duration == 0 {
			result.Duration = elapsed
		}
		results[name] = result
		r.renderer.RenderStepResult(name, result)
	}

	r.renderer.RenderSummary(results, order)

	return firstErr
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/runner/ -v`
Expected: all 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/runner/runner.go internal/runner/runner_test.go
git commit -m "Add pipeline runner with fail-fast and continue-on-error"
```

---

### Task 8: TokenDecode Step

**Files:**
- Create: `internal/steps/token_decode.go`
- Test: `internal/steps/token_decode_test.go`

- [ ] **Step 1: Write tests for JWT decoding**

Create `internal/steps/token_decode_test.go`:

```go
package steps

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
)

// buildTestJWT constructs a fake JWT from header and payload maps.
func buildTestJWT(header, payload map[string]interface{}) string {
	hJSON, _ := json.Marshal(header)
	pJSON, _ := json.Marshal(payload)
	h := base64.RawURLEncoding.EncodeToString(hJSON)
	p := base64.RawURLEncoding.EncodeToString(pJSON)
	return h + "." + p + ".fakesignature"
}

func TestTokenDecodeExecute(t *testing.T) {
	header := map[string]interface{}{"alg": "RS256", "kid": "test-key-id", "typ": "JWT"}
	payload := map[string]interface{}{
		"iss":    "https://test.okta.com",
		"sub":    "user@example.com",
		"aud":    "test-client-id",
		"exp":    1700000000.0,
		"iat":    1699999000.0,
		"groups": []interface{}{"admin", "users"},
	}

	jwt := buildTestJWT(header, payload)

	ctx := NewFlowContext(&Config{}, &http.Client{})
	ctx.IDToken = jwt

	step := NewTokenDecodeStep()
	result, err := step.Execute(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}

	// Check context was populated
	if ctx.TokenHeader["alg"] != "RS256" {
		t.Errorf("TokenHeader alg = %v, want RS256", ctx.TokenHeader["alg"])
	}
	if ctx.TokenClaims["sub"] != "user@example.com" {
		t.Errorf("TokenClaims sub = %v, want user@example.com", ctx.TokenClaims["sub"])
	}
	if ctx.TokenClaims["iss"] != "https://test.okta.com" {
		t.Errorf("TokenClaims iss = %v", ctx.TokenClaims["iss"])
	}
}

func TestTokenDecodeStepName(t *testing.T) {
	step := NewTokenDecodeStep()
	if step.Name() != "TokenDecode" {
		t.Errorf("Name() = %q, want TokenDecode", step.Name())
	}
}

func TestTokenDecodeInvalidJWT(t *testing.T) {
	ctx := NewFlowContext(&Config{}, &http.Client{})
	ctx.IDToken = "not-a-jwt"

	step := NewTokenDecodeStep()
	_, err := step.Execute(ctx)

	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestTokenDecodeEmptyToken(t *testing.T) {
	ctx := NewFlowContext(&Config{}, &http.Client{})
	ctx.IDToken = ""

	step := NewTokenDecodeStep()
	_, err := step.Execute(ctx)

	if err == nil {
		t.Error("expected error for empty token")
	}
}

func TestTokenDecodeBadBase64(t *testing.T) {
	ctx := NewFlowContext(&Config{}, &http.Client{})
	ctx.IDToken = "!!!invalid-base64!!!.!!!also-bad!!!.sig"

	step := NewTokenDecodeStep()
	_, err := step.Execute(ctx)

	if err == nil {
		t.Error("expected error for bad base64")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/steps/ -v -run TestTokenDecode`
Expected: compilation errors

- [ ] **Step 3: Implement TokenDecode step**

Create `internal/steps/token_decode.go`:

```go
package steps

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// TokenDecodeStep decodes a JWT ID token and populates the FlowContext
// with the header and claims for display.
type TokenDecodeStep struct{}

func NewTokenDecodeStep() *TokenDecodeStep {
	return &TokenDecodeStep{}
}

func (s *TokenDecodeStep) Name() string {
	return "TokenDecode"
}

func (s *TokenDecodeStep) Execute(ctx *FlowContext) (*StepResult, error) {
	start := time.Now()

	if ctx.IDToken == "" {
		return nil, &StepError{
			Err:  fmt.Errorf("no ID token available"),
			Hint: "The Okta authentication step must complete before token decode",
		}
	}

	parts := strings.SplitN(ctx.IDToken, ".", 3)
	if len(parts) != 3 {
		return nil, &StepError{
			Err:  fmt.Errorf("invalid JWT format: expected 3 dot-separated parts, got %d", len(parts)),
			Hint: "The token from Okta does not appear to be a valid JWT",
		}
	}

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("decoding JWT header: %w", err),
			Hint: "JWT header contains invalid base64",
		}
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("parsing JWT header JSON: %w", err),
			Hint: "JWT header is not valid JSON",
		}
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("decoding JWT payload: %w", err),
			Hint: "JWT payload contains invalid base64",
		}
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("parsing JWT payload JSON: %w", err),
			Hint: "JWT payload is not valid JSON",
		}
	}

	ctx.TokenHeader = header
	ctx.TokenClaims = claims

	// Build result fields
	var fields []Field

	// Header fields
	for _, key := range []string{"alg", "kid", "typ"} {
		if val, ok := header[key]; ok {
			fields = append(fields, Field{Label: fmt.Sprintf("Header: %s", key), Value: fmt.Sprintf("%v", val)})
		}
	}

	fields = append(fields, Field{Label: "", Value: ""}) // visual separator

	// Claims — display all, but mark trust-policy-relevant ones
	trustRelevant := map[string]bool{"iss": true, "sub": true, "aud": true, "groups": true}
	for key, val := range claims {
		label := fmt.Sprintf("Claim: %s", key)
		if trustRelevant[key] {
			label = fmt.Sprintf("Claim: %s (*)", key)
		}

		var valStr string
		switch v := val.(type) {
		case []interface{}:
			parts := make([]string, len(v))
			for i, item := range v {
				parts[i] = fmt.Sprintf("%v", item)
			}
			valStr = "[" + strings.Join(parts, ", ") + "]"
		default:
			valStr = fmt.Sprintf("%v", v)
		}

		fields = append(fields, Field{Label: label, Value: valStr})
	}

	// Token validity
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		remaining := time.Until(expTime)
		if remaining > 0 {
			fields = append(fields, Field{Label: "Token Expires", Value: fmt.Sprintf("%s (in %s)", expTime.Format(time.RFC3339), remaining.Round(time.Second))})
		} else {
			fields = append(fields, Field{Label: "Token Expires", Value: fmt.Sprintf("%s (EXPIRED %s ago)", expTime.Format(time.RFC3339), (-remaining).Round(time.Second))})
		}
	}

	return &StepResult{
		Title:    "Token Decode",
		Fields:   fields,
		Duration: time.Since(start),
	}, nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/steps/ -v -run TestTokenDecode`
Expected: all 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/steps/token_decode.go internal/steps/token_decode_test.go
git commit -m "Add TokenDecode step for JWT inspection"
```

---

### Task 9: SigV4 Signing

**Files:**
- Create: `internal/s3signer/sigv4.go`
- Test: `internal/s3signer/sigv4_test.go`

- [ ] **Step 1: Write SigV4 tests**

The AWS docs provide test vectors. We'll use a simplified version that validates our signing logic.

Create `internal/s3signer/sigv4_test.go`:

```go
package s3signer

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSignRequestSetsAuthorizationHeader(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://s3.example.com/", nil)

	creds := &Credentials{
		AccessKeyId:    "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:   "session-token-value",
	}

	signTime := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	SignRequest(req, creds, "us-east-1", "s3", signTime)

	auth := req.Header.Get("Authorization")
	if auth == "" {
		t.Fatal("Authorization header should be set")
	}
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256") {
		t.Errorf("Authorization should start with AWS4-HMAC-SHA256, got: %s", auth[:30])
	}
	if !strings.Contains(auth, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("Authorization should contain access key ID")
	}
	if !strings.Contains(auth, "20240115") {
		t.Error("Authorization should contain date stamp")
	}
}

func TestSignRequestSetsSecurityTokenHeader(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://s3.example.com/", nil)

	creds := &Credentials{
		AccessKeyId:    "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:   "my-session-token",
	}

	SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	token := req.Header.Get("X-Amz-Security-Token")
	if token != "my-session-token" {
		t.Errorf("X-Amz-Security-Token = %q, want my-session-token", token)
	}
}

func TestSignRequestNoSessionToken(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://s3.example.com/", nil)

	creds := &Credentials{
		AccessKeyId:    "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	token := req.Header.Get("X-Amz-Security-Token")
	if token != "" {
		t.Error("X-Amz-Security-Token should not be set without session token")
	}
}

func TestSignRequestSetsDateHeader(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://s3.example.com/", nil)

	creds := &Credentials{
		AccessKeyId:    "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	signTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	SignRequest(req, creds, "us-east-1", "s3", signTime)

	date := req.Header.Get("X-Amz-Date")
	if date != "20240615T103000Z" {
		t.Errorf("X-Amz-Date = %q, want 20240615T103000Z", date)
	}
}

func TestSignRequestWithPayload(t *testing.T) {
	body := strings.NewReader("test payload content")
	req, _ := http.NewRequest("PUT", "https://s3.example.com/bucket/key", body)

	creds := &Credentials{
		AccessKeyId:    "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:   "token",
	}

	SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	auth := req.Header.Get("Authorization")
	if auth == "" {
		t.Fatal("Authorization should be set for PUT with body")
	}

	hash := req.Header.Get("X-Amz-Content-Sha256")
	if hash == "" {
		t.Fatal("X-Amz-Content-Sha256 should be set")
	}
	if hash == "UNSIGNED-PAYLOAD" {
		t.Error("payload hash should be computed, not unsigned")
	}
}

func TestSignRequestSetsHostHeader(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://s3.example.com/", nil)

	creds := &Credentials{
		AccessKeyId:    "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	host := req.Header.Get("Host")
	if host != "s3.example.com" {
		t.Errorf("Host = %q, want s3.example.com", host)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/s3signer/ -v`
Expected: compilation errors

- [ ] **Step 3: Implement SigV4 signing**

Create `internal/s3signer/sigv4.go`:

```go
package s3signer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Credentials holds the AWS-style credentials for signing.
type Credentials struct {
	AccessKeyId    string
	SecretAccessKey string
	SessionToken   string
}

// SignRequest signs an HTTP request with AWS Signature Version 4.
// The request is modified in place (headers added).
func SignRequest(req *http.Request, creds *Credentials, region, service string, signTime time.Time) {
	// Set required headers
	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", signTime.Format("20060102T150405Z"))

	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	// Compute payload hash
	payloadHash := computePayloadHash(req)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	// Build canonical request
	dateStamp := signTime.Format("20060102")
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)

	signedHeaders, canonicalHeaders := buildCanonicalHeaders(req)
	canonicalQueryString := buildCanonicalQueryString(req.URL)
	canonicalURI := getCanonicalURI(req.URL)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	// Build string to sign
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		signTime.Format("20060102T150405Z"),
		credentialScope,
		hashSHA256([]byte(canonicalRequest)),
	}, "\n")

	// Derive signing key
	signingKey := deriveSigningKey(creds.SecretAccessKey, dateStamp, region, service)

	// Compute signature
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// Set Authorization header
	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyId, credentialScope, signedHeaders, signature)
	req.Header.Set("Authorization", auth)
}

func computePayloadHash(req *http.Request) string {
	if req.Body == nil || req.Body == http.NoBody {
		return hashSHA256([]byte(""))
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return hashSHA256([]byte(""))
	}
	// Reset body for actual sending
	req.Body = io.NopCloser(strings.NewReader(string(body)))
	req.ContentLength = int64(len(body))

	return hashSHA256(body)
}

func buildCanonicalHeaders(req *http.Request) (signedHeaders, canonicalHeaders string) {
	// Collect headers to sign
	headers := make(map[string]string)
	var headerNames []string

	for name, values := range req.Header {
		lower := strings.ToLower(name)
		// Sign host, x-amz-*, and content-type
		if lower == "host" || strings.HasPrefix(lower, "x-amz-") || lower == "content-type" {
			headers[lower] = strings.TrimSpace(values[0])
			headerNames = append(headerNames, lower)
		}
	}

	sort.Strings(headerNames)

	var canonicalParts []string
	for _, name := range headerNames {
		canonicalParts = append(canonicalParts, name+":"+headers[name])
	}

	signedHeaders = strings.Join(headerNames, ";")
	canonicalHeaders = strings.Join(canonicalParts, "\n") + "\n"
	return
}

func buildCanonicalQueryString(u *url.URL) string {
	params := u.Query()
	if len(params) == 0 {
		return ""
	}

	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		for _, v := range params[k] {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func getCanonicalURI(u *url.URL) string {
	path := u.Path
	if path == "" {
		return "/"
	}
	return path
}

func deriveSigningKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hashSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/s3signer/ -v`
Expected: all 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/s3signer/sigv4.go internal/s3signer/sigv4_test.go
git commit -m "Add AWS SigV4 request signing"
```

---

### Task 10: OktaDeviceAuth Step

**Files:**
- Create: `internal/steps/okta_device_auth.go`
- Test: `internal/steps/okta_device_auth_test.go`

- [ ] **Step 1: Write tests with mock Okta server**

Create `internal/steps/okta_device_auth_test.go`:

```go
package steps

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestOktaDeviceAuthStepName(t *testing.T) {
	step := NewOktaDeviceAuthStep()
	if step.Name() != "OktaDeviceAuth" {
		t.Errorf("Name() = %q, want OktaDeviceAuth", step.Name())
	}
}

func TestOktaDeviceAuthSuccess(t *testing.T) {
	var pollCount atomic.Int32

	// Build a fake JWT for the token response
	fakeJWT := buildTestJWT(
		map[string]interface{}{"alg": "RS256", "typ": "JWT"},
		map[string]interface{}{"sub": "user@test.com", "iss": "https://test.okta.com"},
	)

	mux := http.NewServeMux()

	// Discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// We'll set the URLs after the server starts, so use relative paths
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_authorization_endpoint": "", // filled below
			"token_endpoint":                "", // filled below
		})
	})

	// Device authorization endpoint
	mux.HandleFunc("/v1/device/authorize", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               "test-device-code",
			"user_code":                 "ABCD-1234",
			"verification_uri":          "https://test.okta.com/activate",
			"verification_uri_complete": "https://test.okta.com/activate?user_code=ABCD-1234",
			"expires_in":                300,
			"interval":                  1,
		})
	})

	// Token endpoint — first call returns pending, second returns token
	mux.HandleFunc("/v1/token", func(w http.ResponseWriter, r *http.Request) {
		count := pollCount.Add(1)
		if count < 2 {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "authorization_pending",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id_token":     fakeJWT,
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Re-register discovery with correct URLs
	mux.HandleFunc("/discovery", func(w http.ResponseWriter, r *http.Request) {})
	// Actually, we need to fix the discovery response. Let's use a custom handler.
	// Since we can't re-register, use a separate approach with the server URL.

	// Create a new server with the URL known
	mux2 := http.NewServeMux()
	var serverURL string

	mux2.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_authorization_endpoint": serverURL + "/v1/device/authorize",
			"token_endpoint":                serverURL + "/v1/token",
		})
	})
	mux2.HandleFunc("/v1/device/authorize", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               "test-device-code",
			"user_code":                 "ABCD-1234",
			"verification_uri":          "https://test.okta.com/activate",
			"verification_uri_complete": "https://test.okta.com/activate?user_code=ABCD-1234",
			"expires_in":                300,
			"interval":                  1,
		})
	})

	pollCount.Store(0)
	mux2.HandleFunc("/v1/token", func(w http.ResponseWriter, r *http.Request) {
		count := pollCount.Add(1)
		if count < 2 {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "authorization_pending",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id_token":     fakeJWT,
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	server.Close()
	server = httptest.NewServer(mux2)
	defer server.Close()
	serverURL = server.URL

	ctx := NewFlowContext(&Config{
		OktaTenantURL: server.URL,
		OktaClientID:  "test-client-id",
		OktaScopes:    []string{"openid", "profile"},
	}, server.Client())

	step := NewOktaDeviceAuthStep()
	result, err := step.Execute(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if ctx.IDToken == "" {
		t.Error("IDToken should be set")
	}
	if ctx.AccessToken != "fake-access-token" {
		t.Errorf("AccessToken = %q, want fake-access-token", ctx.AccessToken)
	}
}

func TestOktaDeviceAuthBadDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	ctx := NewFlowContext(&Config{
		OktaTenantURL: server.URL,
		OktaClientID:  "test-client-id",
		OktaScopes:    []string{"openid"},
	}, server.Client())

	step := NewOktaDeviceAuthStep()
	_, err := step.Execute(ctx)

	if err == nil {
		t.Error("expected error for failed discovery")
	}
}

func TestOktaDeviceAuthPreSuppliedToken(t *testing.T) {
	fakeJWT := buildTestJWT(
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{"sub": "user@test.com"},
	)

	ctx := NewFlowContext(&Config{
		PreSuppliedToken: fakeJWT,
	}, &http.Client{})

	step := NewOktaDeviceAuthStep()
	result, err := step.Execute(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if ctx.IDToken != fakeJWT {
		t.Error("IDToken should be set to pre-supplied token")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/steps/ -v -run TestOktaDevice`
Expected: compilation errors

- [ ] **Step 3: Implement OktaDeviceAuth step**

Create `internal/steps/okta_device_auth.go`:

```go
package steps

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OktaDeviceAuthStep performs the OAuth 2.0 device authorization grant flow.
type OktaDeviceAuthStep struct{}

func NewOktaDeviceAuthStep() *OktaDeviceAuthStep {
	return &OktaDeviceAuthStep{}
}

func (s *OktaDeviceAuthStep) Name() string {
	return "OktaDeviceAuth"
}

// discoveryResponse holds the fields we need from OpenID Connect discovery.
type discoveryResponse struct {
	DeviceAuthEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint      string `json:"token_endpoint"`
}

// deviceAuthResponse holds the response from the device authorization endpoint.
type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// tokenResponse holds the response from the token endpoint.
type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

func (s *OktaDeviceAuthStep) Execute(ctx *FlowContext) (*StepResult, error) {
	start := time.Now()

	// If a pre-supplied token is provided, skip the device flow
	if ctx.Config.PreSuppliedToken != "" {
		ctx.IDToken = ctx.Config.PreSuppliedToken
		return &StepResult{
			Title: "Okta Device Auth (pre-supplied token)",
			Fields: []Field{
				{Label: "Mode", Value: "Pre-supplied token (--token)"},
				{Label: "Token", Value: ctx.IDToken, Sensitive: false},
			},
			Duration: time.Since(start),
		}, nil
	}

	// Step 1: OIDC Discovery
	discoveryURL := strings.TrimRight(ctx.Config.OktaTenantURL, "/") + "/.well-known/openid-configuration"
	discovery, err := s.fetchDiscovery(ctx.HTTPClient, discoveryURL)
	if err != nil {
		return nil, err
	}

	var fields []Field
	fields = append(fields, Field{Label: "Discovery URL", Value: discoveryURL})
	fields = append(fields, Field{Label: "Device Auth Endpoint", Value: discovery.DeviceAuthEndpoint})
	fields = append(fields, Field{Label: "Token Endpoint", Value: discovery.TokenEndpoint})

	// Step 2: Request device code
	deviceAuth, err := s.requestDeviceCode(ctx, discovery.DeviceAuthEndpoint)
	if err != nil {
		return nil, err
	}

	fields = append(fields, Field{Label: "", Value: ""})
	fields = append(fields, Field{Label: "User Code", Value: deviceAuth.UserCode})
	fields = append(fields, Field{Label: "Verification URL", Value: deviceAuth.VerificationURIComplete})
	fields = append(fields, Field{Label: "Device Code", Value: deviceAuth.DeviceCode, Sensitive: false})
	fields = append(fields, Field{Label: "Expires In", Value: fmt.Sprintf("%ds", deviceAuth.ExpiresIn)})

	// Print the user-facing message to stdout immediately
	fmt.Printf("\n  Open this URL in your browser:\n")
	fmt.Printf("  %s\n\n", deviceAuth.VerificationURIComplete)
	fmt.Printf("  Or go to %s and enter code: %s\n\n", deviceAuth.VerificationURI, deviceAuth.UserCode)
	fmt.Printf("  Waiting for authorization...\n")

	// Step 3: Poll for token
	interval := deviceAuth.Interval
	if interval < 1 {
		interval = 5
	}
	deadline := time.Now().Add(time.Duration(deviceAuth.ExpiresIn) * time.Second)

	token, err := s.pollForToken(ctx, discovery.TokenEndpoint, deviceAuth.DeviceCode, interval, deadline)
	if err != nil {
		return nil, err
	}

	ctx.IDToken = token.IDToken
	ctx.AccessToken = token.AccessToken

	fields = append(fields, Field{Label: "", Value: ""})
	fields = append(fields, Field{Label: "ID Token", Value: token.IDToken})
	fields = append(fields, Field{Label: "Access Token", Value: token.AccessToken})
	fields = append(fields, Field{Label: "Token Type", Value: token.TokenType})
	fields = append(fields, Field{Label: "Expires In", Value: fmt.Sprintf("%ds", token.ExpiresIn)})

	return &StepResult{
		Title:    "Okta Device Auth",
		Fields:   fields,
		Duration: time.Since(start),
	}, nil
}

func (s *OktaDeviceAuthStep) fetchDiscovery(client *http.Client, url string) (*discoveryResponse, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("fetching OIDC discovery: %w", err),
			Hint: "Check that the Okta tenant URL is correct and reachable",
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, &StepError{
			Err:         fmt.Errorf("OIDC discovery returned HTTP %d", resp.StatusCode),
			HTTPStatus:  resp.StatusCode,
			RawResponse: string(body),
			Hint:        "Check that the Okta tenant URL is correct",
		}
	}

	var discovery discoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("parsing discovery response: %w", err),
			Hint: "The OIDC discovery endpoint returned invalid JSON",
		}
	}
	return &discovery, nil
}

func (s *OktaDeviceAuthStep) requestDeviceCode(ctx *FlowContext, endpoint string) (*deviceAuthResponse, error) {
	data := url.Values{
		"client_id": {ctx.Config.OktaClientID},
		"scope":     {strings.Join(ctx.Config.OktaScopes, " ")},
	}

	resp, err := ctx.HTTPClient.PostForm(endpoint, data)
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("requesting device code: %w", err),
			Hint: "Failed to reach the Okta device authorization endpoint",
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, &StepError{
			Err:         fmt.Errorf("device authorization returned HTTP %d", resp.StatusCode),
			HTTPStatus:  resp.StatusCode,
			RawResponse: string(body),
			Hint:        "Check that client_id is correct and the app is configured for device code grant in Okta",
			Code:        "invalid_client",
		}
	}

	var deviceAuth deviceAuthResponse
	if err := json.Unmarshal(body, &deviceAuth); err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("parsing device authorization response: %w", err),
			Hint: "The device authorization endpoint returned invalid JSON",
		}
	}
	return &deviceAuth, nil
}

func (s *OktaDeviceAuthStep) pollForToken(ctx *FlowContext, endpoint, deviceCode string, interval int, deadline time.Time) (*tokenResponse, error) {
	data := url.Values{
		"client_id":   {ctx.Config.OktaClientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}

	for time.Now().Before(deadline) {
		resp, err := ctx.HTTPClient.PostForm(endpoint, data)
		if err != nil {
			return nil, &StepError{
				Err:  fmt.Errorf("polling token endpoint: %w", err),
				Hint: "Failed to reach the Okta token endpoint",
			}
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var token tokenResponse
		json.Unmarshal(body, &token)

		if resp.StatusCode == 200 && token.IDToken != "" {
			return &token, nil
		}

		if token.Error == "authorization_pending" || token.Error == "slow_down" {
			if token.Error == "slow_down" {
				interval += 5
			}
			time.Sleep(time.Duration(interval) * time.Second)
			continue
		}

		if token.Error != "" {
			return nil, &StepError{
				Err:         fmt.Errorf("token exchange failed: %s", token.ErrorDesc),
				Code:        token.Error,
				HTTPStatus:  resp.StatusCode,
				RawResponse: string(body),
				Hint:        fmt.Sprintf("Okta returned error: %s", token.Error),
			}
		}
	}

	return nil, &StepError{
		Err:  fmt.Errorf("device authorization timed out"),
		Hint: "User did not complete browser authorization within the timeout window",
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/steps/ -v -run TestOktaDevice -timeout 30s`
Expected: all 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/steps/okta_device_auth.go internal/steps/okta_device_auth_test.go
git commit -m "Add OktaDeviceAuth step with device code flow"
```

---

### Task 11: STSAssume Step

**Files:**
- Create: `internal/steps/sts_assume.go`
- Test: `internal/steps/sts_assume_test.go`

- [ ] **Step 1: Write tests with mock STS server**

Create `internal/steps/sts_assume_test.go`:

```go
package steps

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSTSAssumeStepName(t *testing.T) {
	step := NewSTSAssumeStep()
	if step.Name() != "STSAssume" {
		t.Errorf("Name() = %q, want STSAssume", step.Name())
	}
}

func TestSTSAssumeSuccess(t *testing.T) {
	stsResponse := `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIATESTACCESSKEY</AccessKeyId>
      <SecretAccessKey>testsecretkey123456</SecretAccessKey>
      <SessionToken>FwoGZXIvYXdzTestSessionToken</SessionToken>
      <Expiration>2024-01-15T13:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789:assumed-role/test-role/fbsts-validate</Arn>
      <AssumedRoleId>AROATESTROLE:fbsts-validate</AssumedRoleId>
    </AssumedRoleUser>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request parameters
		r.ParseForm()
		if r.Form.Get("Action") != "AssumeRoleWithWebIdentity" {
			t.Errorf("Action = %q, want AssumeRoleWithWebIdentity", r.Form.Get("Action"))
		}
		if r.Form.Get("Version") != "2011-06-15" {
			t.Errorf("Version = %q, want 2011-06-15", r.Form.Get("Version"))
		}
		if r.Form.Get("RoleArn") != "arn:aws:iam::123:role/test" {
			t.Errorf("RoleArn = %q", r.Form.Get("RoleArn"))
		}
		if r.Form.Get("WebIdentityToken") != "fake-jwt-token" {
			t.Errorf("WebIdentityToken = %q", r.Form.Get("WebIdentityToken"))
		}
		w.Header().Set("Content-Type", "text/xml")
		w.Write([]byte(stsResponse))
	}))
	defer server.Close()

	ctx := NewFlowContext(&Config{
		STSEndpoint: server.URL,
		RoleARN:     "arn:aws:iam::123:role/test",
		Duration:    3600,
	}, server.Client())
	ctx.IDToken = "fake-jwt-token"

	step := NewSTSAssumeStep()
	result, err := step.Execute(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if ctx.AccessKeyId != "ASIATESTACCESSKEY" {
		t.Errorf("AccessKeyId = %q", ctx.AccessKeyId)
	}
	if ctx.SecretAccessKey != "testsecretkey123456" {
		t.Errorf("SecretAccessKey = %q", ctx.SecretAccessKey)
	}
	if ctx.SessionToken != "FwoGZXIvYXdzTestSessionToken" {
		t.Errorf("SessionToken = %q", ctx.SessionToken)
	}
	if ctx.AssumedRoleARN != "arn:aws:sts::123456789:assumed-role/test-role/fbsts-validate" {
		t.Errorf("AssumedRoleARN = %q", ctx.AssumedRoleARN)
	}
}

func TestSTSAssumeAccessDenied(t *testing.T) {
	errorResponse := `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>Not authorized to perform sts:AssumeRoleWithWebIdentity</Message>
  </Error>
</ErrorResponse>`

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(errorResponse))
	}))
	defer server.Close()

	ctx := NewFlowContext(&Config{
		STSEndpoint: server.URL,
		RoleARN:     "arn:aws:iam::123:role/test",
		Duration:    3600,
	}, server.Client())
	ctx.IDToken = "fake-jwt-token"

	step := NewSTSAssumeStep()
	_, err := step.Execute(ctx)

	if err == nil {
		t.Fatal("expected error for access denied")
	}
	se, ok := err.(*StepError)
	if !ok {
		t.Fatalf("expected *StepError, got %T", err)
	}
	if se.Code != "AccessDenied" {
		t.Errorf("error code = %q, want AccessDenied", se.Code)
	}
	if se.HTTPStatus != 403 {
		t.Errorf("HTTP status = %d, want 403", se.HTTPStatus)
	}
}

func TestSTSAssumeNoToken(t *testing.T) {
	ctx := NewFlowContext(&Config{
		STSEndpoint: "https://example.com",
		RoleARN:     "arn:aws:iam::123:role/test",
	}, &http.Client{})
	// IDToken not set

	step := NewSTSAssumeStep()
	_, err := step.Execute(ctx)

	if err == nil {
		t.Error("expected error when IDToken is empty")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/steps/ -v -run TestSTSAssume`
Expected: compilation errors

- [ ] **Step 3: Implement STSAssume step**

Create `internal/steps/sts_assume.go`:

```go
package steps

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// STSAssumeStep calls AssumeRoleWithWebIdentity on the FlashBlade STS VIP.
type STSAssumeStep struct{}

func NewSTSAssumeStep() *STSAssumeStep {
	return &STSAssumeStep{}
}

func (s *STSAssumeStep) Name() string {
	return "STSAssume"
}

// XML response structures for AssumeRoleWithWebIdentity
type assumeRoleResponse struct {
	XMLName xml.Name            `xml:"AssumeRoleWithWebIdentityResponse"`
	Result  assumeRoleResult    `xml:"AssumeRoleWithWebIdentityResult"`
}

type assumeRoleResult struct {
	Credentials     stsCredentials  `xml:"Credentials"`
	AssumedRoleUser assumedRoleUser `xml:"AssumedRoleUser"`
}

type stsCredentials struct {
	AccessKeyId     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

type assumedRoleUser struct {
	Arn           string `xml:"Arn"`
	AssumedRoleId string `xml:"AssumedRoleId"`
}

type stsErrorResponse struct {
	XMLName xml.Name `xml:"ErrorResponse"`
	Error   stsError `xml:"Error"`
}

type stsError struct {
	Type    string `xml:"Type"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// STS error code to diagnostic hint mapping
var stsHints = map[string]string{
	"AccessDenied":          "Check that the role's trust policy includes your OIDC provider and the aud/sub claims match",
	"InvalidIdentityToken":  "Token may be expired or the FlashBlade cannot reach the Okta JWKS endpoint to validate signatures",
	"MalformedPolicyDocument": "The role's trust policy syntax is invalid — check conditions and principal format",
	"ExpiredTokenException":  "The OIDC token has expired. Re-authenticate with Okta and try again",
	"RegionDisabledException": "STS is not enabled for this region on the FlashBlade",
}

func (s *STSAssumeStep) Execute(ctx *FlowContext) (*StepResult, error) {
	start := time.Now()

	if ctx.IDToken == "" {
		return nil, &StepError{
			Err:  fmt.Errorf("no ID token available for STS call"),
			Hint: "The Okta authentication step must complete successfully before STS",
		}
	}

	sessionName := fmt.Sprintf("fbsts-validate-%d", time.Now().Unix())
	duration := ctx.Config.Duration
	if duration == 0 {
		duration = 3600
	}

	// Build request parameters
	params := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {ctx.Config.RoleARN},
		"RoleSessionName":  {sessionName},
		"WebIdentityToken": {ctx.IDToken},
		"DurationSeconds":  {fmt.Sprintf("%d", duration)},
	}

	endpoint := strings.TrimRight(ctx.Config.STSEndpoint, "/") + "/"

	var fields []Field
	fields = append(fields, Field{Label: "STS Endpoint", Value: endpoint})
	fields = append(fields, Field{Label: "Action", Value: "AssumeRoleWithWebIdentity"})
	fields = append(fields, Field{Label: "RoleArn", Value: ctx.Config.RoleARN})
	fields = append(fields, Field{Label: "RoleSessionName", Value: sessionName})
	fields = append(fields, Field{Label: "DurationSeconds", Value: fmt.Sprintf("%d", duration)})
	fields = append(fields, Field{Label: "WebIdentityToken", Value: ctx.IDToken})

	// Make the STS request
	resp, err := ctx.HTTPClient.PostForm(endpoint, params)
	if err != nil {
		return nil, &StepError{
			Err:  fmt.Errorf("STS request failed: %w", err),
			Hint: "Check that the STS endpoint is correct and reachable. If using a self-signed certificate, try --insecure",
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	fields = append(fields, Field{Label: "", Value: ""})
	fields = append(fields, Field{Label: "HTTP Status", Value: fmt.Sprintf("%d", resp.StatusCode)})

	if resp.StatusCode != 200 {
		// Try to parse the error response
		var errResp stsErrorResponse
		xml.Unmarshal(body, &errResp)

		code := errResp.Error.Code
		hint := stsHints[code]
		if hint == "" {
			hint = fmt.Sprintf("STS returned error: %s — %s", code, errResp.Error.Message)
		}

		return nil, &StepError{
			Err:         fmt.Errorf("STS AssumeRoleWithWebIdentity failed: %s", errResp.Error.Message),
			Code:        code,
			HTTPStatus:  resp.StatusCode,
			RawResponse: string(body),
			Hint:        hint,
		}
	}

	// Parse success response
	var stsResp assumeRoleResponse
	if err := xml.Unmarshal(body, &stsResp); err != nil {
		return nil, &StepError{
			Err:         fmt.Errorf("parsing STS response: %w", err),
			RawResponse: string(body),
			Hint:        "The STS endpoint returned a response that could not be parsed as XML",
		}
	}

	creds := stsResp.Result.Credentials
	role := stsResp.Result.AssumedRoleUser

	ctx.AccessKeyId = creds.AccessKeyId
	ctx.SecretAccessKey = creds.SecretAccessKey
	ctx.SessionToken = creds.SessionToken
	ctx.AssumedRoleARN = role.Arn

	if expTime, err := time.Parse(time.RFC3339, creds.Expiration); err == nil {
		ctx.Expiration = expTime
	}

	fields = append(fields, Field{Label: "AccessKeyId", Value: creds.AccessKeyId})
	fields = append(fields, Field{Label: "SecretAccessKey", Value: creds.SecretAccessKey, Sensitive: true})
	fields = append(fields, Field{Label: "SessionToken", Value: creds.SessionToken})
	fields = append(fields, Field{Label: "Expiration", Value: creds.Expiration})
	fields = append(fields, Field{Label: "AssumedRole ARN", Value: role.Arn})
	fields = append(fields, Field{Label: "AssumedRoleId", Value: role.AssumedRoleId})

	return &StepResult{
		Title:    "STS AssumeRoleWithWebIdentity",
		Fields:   fields,
		Duration: time.Since(start),
	}, nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/steps/ -v -run TestSTSAssume`
Expected: all 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/steps/sts_assume.go internal/steps/sts_assume_test.go
git commit -m "Add STSAssume step for AssumeRoleWithWebIdentity"
```

---

### Task 12: S3Validate Step

**Files:**
- Create: `internal/steps/s3_validate.go`
- Test: `internal/steps/s3_validate_test.go`

- [ ] **Step 1: Write tests with mock S3 server**

Create `internal/steps/s3_validate_test.go`:

```go
package steps

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestS3ValidateStepName(t *testing.T) {
	step := NewS3ValidateStep()
	if step.Name() != "S3Validate" {
		t.Errorf("Name() = %q, want S3Validate", step.Name())
	}
}

func TestS3ValidateSuccess(t *testing.T) {
	var storedBody string

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/":
			// ListBuckets
			w.Header().Set("Content-Type", "application/xml")
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult>
  <Buckets>
    <Bucket><Name>test-bucket</Name></Bucket>
  </Buckets>
</ListAllMyBucketsResult>`))

		case r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/test-bucket/"):
			// PutObject
			body, _ := io.ReadAll(r.Body)
			storedBody = string(body)
			w.WriteHeader(200)

		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/test-bucket/"):
			// GetObject
			w.Write([]byte(storedBody))

		case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/test-bucket/"):
			// DeleteObject
			w.WriteHeader(204)

		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	ctx := NewFlowContext(&Config{
		DataEndpoint:  server.URL,
		TestBucket:    "test-bucket",
		TestKeyPrefix: "fbsts-validate/",
	}, server.Client())
	ctx.AccessKeyId = "ASIATESTACCESSKEY"
	ctx.SecretAccessKey = "testsecretkey123456"
	ctx.SessionToken = "test-session-token"

	step := NewS3ValidateStep()
	result, err := step.Execute(ctx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if len(result.SubSteps) != 4 {
		t.Errorf("expected 4 substeps, got %d", len(result.SubSteps))
	}
	for i, ss := range result.SubSteps {
		if ss.Status != StatusPass {
			t.Errorf("substep %d (%s) should pass, got status %d, error: %s", i, ss.Name, ss.Status, ss.Error)
		}
	}
}

func TestS3ValidatePutForbidden(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/":
			w.Write([]byte(`<ListAllMyBucketsResult><Buckets><Bucket><Name>test-bucket</Name></Bucket></Buckets></ListAllMyBucketsResult>`))
		case r.Method == "PUT":
			w.WriteHeader(403)
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	ctx := NewFlowContext(&Config{
		DataEndpoint:    server.URL,
		TestBucket:      "test-bucket",
		TestKeyPrefix:   "fbsts-validate/",
		ContinueOnError: false,
	}, server.Client())
	ctx.AccessKeyId = "ASIATESTACCESSKEY"
	ctx.SecretAccessKey = "testsecretkey123456"
	ctx.SessionToken = "test-session-token"

	step := NewS3ValidateStep()
	_, err := step.Execute(ctx)

	if err == nil {
		t.Fatal("expected error for forbidden PUT")
	}
}

func TestS3ValidateNoCreds(t *testing.T) {
	ctx := NewFlowContext(&Config{
		DataEndpoint: "https://example.com",
		TestBucket:   "test-bucket",
	}, &http.Client{})
	// No credentials set

	step := NewS3ValidateStep()
	_, err := step.Execute(ctx)

	if err == nil {
		t.Error("expected error when credentials are missing")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/steps/ -v -run TestS3Validate`
Expected: compilation errors

- [ ] **Step 3: Implement S3Validate step**

Create `internal/steps/s3_validate.go`:

```go
package steps

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/pure-experimental/rp-fbstsvalidator/internal/s3signer"
)

// S3ValidateStep performs a CRUD cycle against the FlashBlade Data VIP
// using the temporary STS credentials.
type S3ValidateStep struct{}

func NewS3ValidateStep() *S3ValidateStep {
	return &S3ValidateStep{}
}

func (s *S3ValidateStep) Name() string {
	return "S3Validate"
}

func (s *S3ValidateStep) Execute(ctx *FlowContext) (*StepResult, error) {
	start := time.Now()

	if ctx.AccessKeyId == "" || ctx.SecretAccessKey == "" {
		return nil, &StepError{
			Err:  fmt.Errorf("no STS credentials available"),
			Hint: "The STS step must complete successfully before S3 validation",
		}
	}

	creds := &s3signer.Credentials{
		AccessKeyId:    ctx.AccessKeyId,
		SecretAccessKey: ctx.SecretAccessKey,
		SessionToken:   ctx.SessionToken,
	}

	endpoint := strings.TrimRight(ctx.Config.DataEndpoint, "/")
	bucket := ctx.Config.TestBucket
	keyPrefix := ctx.Config.TestKeyPrefix
	if keyPrefix == "" {
		keyPrefix = "fbsts-validate/"
	}
	objectKey := fmt.Sprintf("%s%d.txt", keyPrefix, time.Now().Unix())
	testContent := fmt.Sprintf("fbsts validation test object created at %s", time.Now().Format(time.RFC3339))

	var fields []Field
	fields = append(fields, Field{Label: "Data Endpoint", Value: endpoint})
	fields = append(fields, Field{Label: "Bucket", Value: bucket})
	fields = append(fields, Field{Label: "Object Key", Value: objectKey})

	var subSteps []SubStep

	// 1. ListBuckets
	listResult := s.doListBuckets(ctx.HTTPClient, creds, endpoint)
	subSteps = append(subSteps, listResult)
	if listResult.Status == StatusFail && !ctx.Config.ContinueOnError {
		return nil, s.buildError("ListBuckets", listResult)
	}

	// 2. PutObject
	contentHash := sha256Hash([]byte(testContent))
	putResult := s.doPutObject(ctx.HTTPClient, creds, endpoint, bucket, objectKey, testContent)
	putResult.Fields = append(putResult.Fields, Field{Label: "Content SHA-256", Value: contentHash})
	subSteps = append(subSteps, putResult)
	if putResult.Status == StatusFail && !ctx.Config.ContinueOnError {
		return nil, s.buildError("PutObject", putResult)
	}

	// 3. GetObject
	getResult := s.doGetObject(ctx.HTTPClient, creds, endpoint, bucket, objectKey, contentHash)
	subSteps = append(subSteps, getResult)
	if getResult.Status == StatusFail && !ctx.Config.ContinueOnError {
		return nil, s.buildError("GetObject", getResult)
	}

	// 4. DeleteObject
	deleteResult := s.doDeleteObject(ctx.HTTPClient, creds, endpoint, bucket, objectKey)
	subSteps = append(subSteps, deleteResult)
	if deleteResult.Status == StatusFail && !ctx.Config.ContinueOnError {
		return nil, s.buildError("DeleteObject", deleteResult)
	}

	ctx.S3Results = []S3OpResult{}
	for _, ss := range subSteps {
		ctx.S3Results = append(ctx.S3Results, S3OpResult{
			Operation: ss.Name,
			Bucket:    bucket,
			Key:       objectKey,
			Pass:      ss.Status == StatusPass,
			Duration:  ss.Duration,
			Error:     ss.Error,
		})
	}

	return &StepResult{
		Title:    "S3 Validate (CRUD)",
		Fields:   fields,
		SubSteps: subSteps,
		Duration: time.Since(start),
	}, nil
}

func (s *S3ValidateStep) doListBuckets(client *http.Client, creds *s3signer.Credentials, endpoint string) SubStep {
	opStart := time.Now()

	req, _ := http.NewRequest("GET", endpoint+"/", nil)
	s3signer.SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	resp, err := client.Do(req)
	if err != nil {
		return SubStep{Name: "ListBuckets", Status: StatusFail, Duration: time.Since(opStart), Error: err.Error()}
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) // drain

	if resp.StatusCode != 200 {
		return SubStep{
			Name: "ListBuckets", Status: StatusFail, Duration: time.Since(opStart),
			Error:  fmt.Sprintf("HTTP %d", resp.StatusCode),
			Fields: []Field{{Label: "HTTP Status", Value: fmt.Sprintf("%d", resp.StatusCode)}},
		}
	}

	return SubStep{
		Name: "ListBuckets", Status: StatusPass, Duration: time.Since(opStart),
		Fields: []Field{{Label: "HTTP Status", Value: "200"}},
	}
}

func (s *S3ValidateStep) doPutObject(client *http.Client, creds *s3signer.Credentials, endpoint, bucket, key, content string) SubStep {
	opStart := time.Now()

	url := fmt.Sprintf("%s/%s/%s", endpoint, bucket, key)
	req, _ := http.NewRequest("PUT", url, strings.NewReader(content))
	req.Header.Set("Content-Type", "text/plain")
	s3signer.SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	resp, err := client.Do(req)
	if err != nil {
		return SubStep{Name: "PutObject", Status: StatusFail, Duration: time.Since(opStart), Error: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return SubStep{
			Name: "PutObject", Status: StatusFail, Duration: time.Since(opStart),
			Error:  fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)),
			Fields: []Field{{Label: "HTTP Status", Value: fmt.Sprintf("%d", resp.StatusCode)}},
		}
	}

	return SubStep{
		Name: "PutObject", Status: StatusPass, Duration: time.Since(opStart),
		Fields: []Field{{Label: "HTTP Status", Value: "200"}},
	}
}

func (s *S3ValidateStep) doGetObject(client *http.Client, creds *s3signer.Credentials, endpoint, bucket, key, expectedHash string) SubStep {
	opStart := time.Now()

	url := fmt.Sprintf("%s/%s/%s", endpoint, bucket, key)
	req, _ := http.NewRequest("GET", url, nil)
	s3signer.SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	resp, err := client.Do(req)
	if err != nil {
		return SubStep{Name: "GetObject", Status: StatusFail, Duration: time.Since(opStart), Error: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return SubStep{
			Name: "GetObject", Status: StatusFail, Duration: time.Since(opStart),
			Error:  fmt.Sprintf("HTTP %d", resp.StatusCode),
			Fields: []Field{{Label: "HTTP Status", Value: fmt.Sprintf("%d", resp.StatusCode)}},
		}
	}

	gotHash := sha256Hash(body)
	fields := []Field{
		{Label: "HTTP Status", Value: "200"},
		{Label: "Content SHA-256", Value: gotHash},
	}

	if gotHash != expectedHash {
		return SubStep{
			Name: "GetObject", Status: StatusFail, Duration: time.Since(opStart),
			Error:  fmt.Sprintf("content mismatch: expected %s, got %s", expectedHash, gotHash),
			Fields: fields,
		}
	}

	fields = append(fields, Field{Label: "Content Verified", Value: "match"})
	return SubStep{
		Name: "GetObject", Status: StatusPass, Duration: time.Since(opStart),
		Fields: fields,
	}
}

func (s *S3ValidateStep) doDeleteObject(client *http.Client, creds *s3signer.Credentials, endpoint, bucket, key string) SubStep {
	opStart := time.Now()

	url := fmt.Sprintf("%s/%s/%s", endpoint, bucket, key)
	req, _ := http.NewRequest("DELETE", url, nil)
	s3signer.SignRequest(req, creds, "us-east-1", "s3", time.Now().UTC())

	resp, err := client.Do(req)
	if err != nil {
		return SubStep{Name: "DeleteObject", Status: StatusFail, Duration: time.Since(opStart), Error: err.Error()}
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	// 204 No Content or 200 OK are both success
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return SubStep{
			Name: "DeleteObject", Status: StatusFail, Duration: time.Since(opStart),
			Error:  fmt.Sprintf("HTTP %d", resp.StatusCode),
			Fields: []Field{{Label: "HTTP Status", Value: fmt.Sprintf("%d", resp.StatusCode)}},
		}
	}

	return SubStep{
		Name: "DeleteObject", Status: StatusPass, Duration: time.Since(opStart),
		Fields: []Field{{Label: "HTTP Status", Value: fmt.Sprintf("%d", resp.StatusCode)}},
	}
}

func (s *S3ValidateStep) buildError(op string, ss SubStep) *StepError {
	hint := fmt.Sprintf("Temporary credentials are valid but the role's access policy may not grant s3:%s", op)
	if strings.Contains(ss.Error, "403") {
		hint = "Temporary credentials are valid but the role's access policy doesn't grant this S3 operation"
	}
	return &StepError{
		Err:  fmt.Errorf("S3 %s failed: %s", op, ss.Error),
		Hint: hint,
	}
}

func sha256Hash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/steps/ -v -run TestS3Validate`
Expected: all 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add internal/steps/s3_validate.go internal/steps/s3_validate_test.go
git commit -m "Add S3Validate step with CRUD cycle"
```

---

### Task 13: CLI Wiring

**Files:**
- Modify: `cmd/fbsts/main.go`
- Create: `.fbsts.toml.example`

- [ ] **Step 1: Implement the full CLI with cobra**

Replace `cmd/fbsts/main.go` with:

```go
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/pure-experimental/rp-fbstsvalidator/internal/config"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/render"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/runner"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

var version = "dev"

var flags config.FlagOverrides
var configPath string

func main() {
	rootCmd := &cobra.Command{
		Use:   "fbsts",
		Short: "FlashBlade STS Validator",
		Long:  "Validates STS (Security Token Service) functionality on Pure Storage FlashBlade arrays for object storage.",
	}

	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Run the full STS validation flow",
		Long:  "Authenticates with Okta via device code flow, obtains temporary credentials via AssumeRoleWithWebIdentity, and validates them with S3 CRUD operations.",
		RunE:  runValidate,
	}

	// Okta flags
	validateCmd.Flags().StringVar(&flags.OktaURL, "okta-url", "", "Okta tenant URL")
	validateCmd.Flags().StringVar(&flags.ClientID, "client-id", "", "Okta application client ID")
	validateCmd.Flags().StringVar(&flags.Scopes, "scopes", "", "OIDC scopes (comma-separated)")

	// FlashBlade flags
	validateCmd.Flags().StringVar(&flags.STSEndpoint, "sts-endpoint", "", "FlashBlade STS VIP URL")
	validateCmd.Flags().StringVar(&flags.DataEndpoint, "data-endpoint", "", "FlashBlade Data VIP URL")
	validateCmd.Flags().StringVar(&flags.RoleARN, "role-arn", "", "Role ARN to assume")
	validateCmd.Flags().StringVar(&flags.Account, "account", "", "Object store account name")

	// S3 flags
	validateCmd.Flags().StringVar(&flags.Bucket, "bucket", "", "Test bucket name")
	validateCmd.Flags().StringVar(&flags.KeyPrefix, "key-prefix", "", "Test object key prefix")

	// TLS flags
	validateCmd.Flags().BoolVar(&flags.Insecure, "insecure", false, "Skip TLS certificate verification")
	validateCmd.Flags().StringVar(&flags.CACert, "ca-cert", "", "Path to custom CA certificate PEM file")

	// Behavior flags
	validateCmd.Flags().BoolVar(&flags.ContinueOnError, "continue-on-error", false, "Continue through all steps even if one fails")
	validateCmd.Flags().StringVar(&flags.Token, "token", "", "Skip Okta auth, use a pre-supplied JWT")
	validateCmd.Flags().IntVar(&flags.Duration, "duration", 0, "STS session duration in seconds")

	// Config flag
	validateCmd.Flags().StringVar(&configPath, "config", "", "Explicit config file path")

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

	rootCmd.AddCommand(validateCmd, initCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runValidate(cmd *cobra.Command, args []string) error {
	// Determine config file paths
	homeDir, _ := os.UserHomeDir()
	homeCfg := filepath.Join(homeDir, ".fbsts.toml")
	localCfg := ".fbsts.toml"

	// Track if --insecure was explicitly set
	if cmd.Flags().Changed("insecure") {
		flags.InsecureSet = true
	}

	// If --token was passed, set it as pre-supplied
	if flags.Token != "" {
		flags.InsecureSet = true // preserve any existing insecure flag
	}

	// Load and resolve config
	cfg, err := config.ResolveConfig(homeCfg, localCfg, configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		return err
	}

	// Apply CLI flag overrides
	config.ApplyOverrides(cfg, &flags)

	// Apply duration override
	if flags.Duration > 0 {
		// Will be set on steps.Config
	}

	// Prompt for missing required values
	reader := bufio.NewReader(os.Stdin)
	if flags.Token == "" {
		// Only prompt for Okta values if not using pre-supplied token
		if err := config.PromptMissing(cfg, reader); err != nil {
			return fmt.Errorf("configuration incomplete: %w", err)
		}
	}

	// Convert to steps config
	stepsCfg := cfg.ToStepsConfig()
	stepsCfg.PreSuppliedToken = flags.Token
	stepsCfg.ContinueOnError = flags.ContinueOnError
	if flags.Duration > 0 {
		stepsCfg.Duration = flags.Duration
	}

	// Create HTTP client with TLS config
	httpClient, err := config.NewHTTPClient(stepsCfg.Insecure, stepsCfg.CACert)
	if err != nil {
		return fmt.Errorf("creating HTTP client: %w", err)
	}

	// Set up renderer
	renderer := render.NewPanelRenderer(os.Stdout)

	// Show TLS warning if insecure
	if stepsCfg.Insecure {
		renderer.RenderWarning("TLS certificate verification is disabled (--insecure)")
	}

	// Build the pipeline
	pipeline := []steps.Step{
		steps.NewOktaDeviceAuthStep(),
		steps.NewTokenDecodeStep(),
		steps.NewSTSAssumeStep(),
		steps.NewS3ValidateStep(),
	}

	// Create flow context and run
	ctx := steps.NewFlowContext(stepsCfg, httpClient)
	r := runner.New(renderer)

	if err := r.Run(ctx, pipeline, stepsCfg.ContinueOnError); err != nil {
		os.Exit(1)
	}

	return nil
}

func runInit(cmd *cobra.Command, args []string) error {
	target := ".fbsts.toml"
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("%s already exists", target)
	}

	content := `# FlashBlade STS Validator Configuration
# See: fbsts validate --help for all available options

[okta]
tenant_url = ""
client_id = ""
scopes = ["openid", "profile", "groups"]

[flashblade]
sts_endpoint = ""
data_endpoint = ""
role_arn = ""
account = ""

[s3]
test_bucket = ""
test_key_prefix = "fbsts-validate/"

[tls]
insecure = false
ca_cert = ""
`

	if err := os.WriteFile(target, []byte(content), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", target, err)
	}

	fmt.Printf("Created %s — edit it with your environment details\n", target)
	return nil
}
```

- [ ] **Step 2: Create the example config file**

Create `.fbsts.toml.example`:

```toml
# FlashBlade STS Validator Configuration
# Copy this to ~/.fbsts.toml or ./.fbsts.toml and fill in your values.
# CLI flags override config file values. See: fbsts validate --help

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
# Set insecure = true for FlashBlade arrays with self-signed certificates
insecure = false
# Or provide a custom CA certificate
ca_cert = ""
```

- [ ] **Step 3: Build and verify**

Run: `go build -o fbsts ./cmd/fbsts && ./fbsts --help`
Expected: prints the help text with validate, init, version subcommands

Run: `./fbsts version`
Expected: prints `fbsts dev`

Run: `./fbsts validate --help`
Expected: prints all flags (--okta-url, --sts-endpoint, --insecure, etc.)

- [ ] **Step 4: Commit**

```bash
git add cmd/fbsts/main.go .fbsts.toml.example
git commit -m "Add CLI with validate, init, and version commands"
```

---

### Task 14: Full Test Suite and Build Verification

**Files:**
- None new — runs existing tests and build

- [ ] **Step 1: Run the complete test suite**

Run: `go test ./... -v -timeout 60s`
Expected: all tests across all packages PASS

- [ ] **Step 2: Run go vet**

Run: `go vet ./...`
Expected: no issues

- [ ] **Step 3: Build for multiple platforms**

```bash
GOOS=darwin GOARCH=arm64 go build -o fbsts-darwin-arm64 ./cmd/fbsts
GOOS=darwin GOARCH=amd64 go build -o fbsts-darwin-amd64 ./cmd/fbsts
GOOS=linux GOARCH=amd64 go build -o fbsts-linux-amd64 ./cmd/fbsts
```

Expected: all three binaries built without error

- [ ] **Step 4: Clean up build artifacts and verify final state**

```bash
rm -f fbsts fbsts-darwin-arm64 fbsts-darwin-amd64 fbsts-linux-amd64
```

Add binaries to `.gitignore` if not already covered (they are — `fbsts` matches).

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "Finalize project: all tests passing, multi-platform build verified"
```
