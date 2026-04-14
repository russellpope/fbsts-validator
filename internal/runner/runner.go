package runner

import (
	"fmt"
	"time"

	"github.com/pure-experimental/rp-fbstsvalidator/internal/render"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

type Runner struct {
	renderer render.Renderer
}

func New(renderer render.Renderer) *Runner {
	return &Runner{renderer: renderer}
}

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
