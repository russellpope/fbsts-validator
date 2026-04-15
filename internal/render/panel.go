package render

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

// Lipgloss styles for PanelRenderer.
var (
	styleTitle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	styleLabel   = lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Width(22)
	styleValue   = lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	stylePass    = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	styleFail    = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	styleWarning = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true)
	styleHint    = lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Italic(true)

	borderResult  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	borderError   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("9")).Padding(0, 1)
	borderSummary = lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).Padding(0, 1)
)

// PanelRenderer writes styled terminal panels to an io.Writer.
type PanelRenderer struct {
	w io.Writer
}

// NewPanelRenderer creates a PanelRenderer that writes to w.
func NewPanelRenderer(w io.Writer) *PanelRenderer {
	return &PanelRenderer{w: w}
}

// RenderStepStart prints a header line announcing the start of a step.
func (r *PanelRenderer) RenderStepStart(name string) {
	fmt.Fprintln(r.w, styleTitle.Render("► "+name))
}

// RenderStepResult renders a bordered panel with the step's results.
func (r *PanelRenderer) RenderStepResult(name string, result *steps.StepResult) {
	var sb strings.Builder

	// Title row
	sb.WriteString(styleTitle.Render(result.Title))
	sb.WriteString("\n")

	// Fields
	for _, f := range result.Fields {
		label := styleLabel.Render(f.Label)
		val := styleValue.Render(MaskField(f.Value, f.Sensitive))
		sb.WriteString(fmt.Sprintf("%s  %s\n", label, val))
	}

	// Sub-steps
	for _, sub := range result.SubSteps {
		var marker string
		if sub.Status == steps.StatusPass {
			marker = stylePass.Render("✓")
		} else {
			marker = styleFail.Render("✗")
		}
		line := fmt.Sprintf("  %s  %s  (%s)", marker, sub.Name, sub.Duration)
		if sub.Error != "" {
			line += "  " + styleFail.Render(sub.Error)
		}
		sb.WriteString(line + "\n")
	}

	// Duration footer
	sb.WriteString(styleLabel.Render("Duration") + "  " + styleValue.Render(result.Duration.String()))

	panel := borderResult.Render(sb.String())
	fmt.Fprintln(r.w, panel)
}

// RenderStepError renders a red-bordered panel with the error details and hint.
func (r *PanelRenderer) RenderStepError(name string, err error) {
	var sb strings.Builder

	sb.WriteString(styleFail.Render("✗ "+name) + "\n")

	var stepErr *steps.StepError
	if errors.As(err, &stepErr) {
		if stepErr.Code != "" {
			sb.WriteString(styleLabel.Render("Code") + "  " + styleValue.Render(stepErr.Code) + "\n")
		}
		if stepErr.HTTPStatus != 0 {
			sb.WriteString(styleLabel.Render("HTTP") + "  " + styleValue.Render(fmt.Sprintf("%d", stepErr.HTTPStatus)) + "\n")
		}
		sb.WriteString(styleLabel.Render("Error") + "  " + styleValue.Render(stepErr.Err.Error()) + "\n")
		if stepErr.Hint != "" {
			sb.WriteString(styleHint.Render("Hint: "+stepErr.Hint) + "\n")
		}
	} else {
		sb.WriteString(styleLabel.Render("Error") + "  " + styleValue.Render(err.Error()) + "\n")
	}

	panel := borderError.Render(sb.String())
	fmt.Fprintln(r.w, panel)
}

// RenderSummary renders a double-bordered summary table of all step results.
func (r *PanelRenderer) RenderSummary(results map[string]*steps.StepResult, order []string) {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("Summary") + "\n")

	for _, key := range order {
		result, ok := results[key]
		if !ok {
			continue
		}
		label := styleLabel.Render(result.Title)
		dur := styleValue.Render(result.Duration.String())
		sb.WriteString(fmt.Sprintf("%s  %s\n", label, dur))
	}

	// Collect and display failure details from SubSteps.
	var failures []string
	for _, key := range order {
		result, ok := results[key]
		if !ok {
			continue
		}
		for _, sub := range result.SubSteps {
			if sub.Status == steps.StatusFail && sub.Error != "" {
				failures = append(failures, fmt.Sprintf("  %s: %s", sub.Name, sub.Error))
			}
		}
	}
	if len(failures) > 0 {
		sb.WriteString("\n" + styleFail.Render("Failures:") + "\n")
		for _, f := range failures {
			sb.WriteString(f + "\n")
		}
	}

	panel := borderSummary.Render(sb.String())
	fmt.Fprintln(r.w, panel)
}

// RenderWarning prints a styled warning message.
func (r *PanelRenderer) RenderWarning(msg string) {
	fmt.Fprintln(r.w, styleWarning.Render("⚠  "+msg))
}
