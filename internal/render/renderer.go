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
