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

	// Keycloak
	KeycloakIssuerURL string
	KeycloakClientID  string
	KeycloakScopes    []string

	// EntraID
	EntraIDIssuerURL string
	EntraIDClientID  string
	EntraIDScopes    []string

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
	ContinueOnError  bool
	PreSuppliedToken string
	Duration         int
	Unmask           bool
	EmitTokenPath    string
}

// FlowContext carries state between pipeline steps.
type FlowContext struct {
	Config     *Config
	HTTPClient *http.Client

	// Set by DeviceAuth
	IDToken     string
	AccessToken string

	// Set by TokenDecode
	TokenHeader map[string]interface{}
	TokenClaims map[string]interface{}

	// Set by STSAssume
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	AssumedRoleARN  string

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
	Err         error
	Hint        string
	Code        string // parsed error code (e.g., "AccessDenied")
	HTTPStatus  int
	RawResponse string
}

func (e *StepError) Error() string {
	return e.Err.Error()
}

func (e *StepError) Unwrap() error {
	return e.Err
}
