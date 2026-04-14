package runner

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/pure-experimental/rp-fbstsvalidator/internal/render"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

type mockStep struct {
	name     string
	result   *steps.StepResult
	err      error
	executed bool
}

func (m *mockStep) Name() string { return m.name }
func (m *mockStep) Execute(ctx *steps.FlowContext) (*steps.StepResult, error) {
	m.executed = true
	time.Sleep(1 * time.Millisecond)
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
