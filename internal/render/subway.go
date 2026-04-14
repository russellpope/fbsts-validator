package render

import (
	"errors"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

// ---------------------------------------------------------------------------
// Station status
// ---------------------------------------------------------------------------

type stationStatus int

const (
	stationPending stationStatus = iota
	stationRunning
	stationComplete
	stationFailed
)

// ---------------------------------------------------------------------------
// Station
// ---------------------------------------------------------------------------

type station struct {
	name   string
	status stationStatus
	result *steps.StepResult
	err    error
}

// ---------------------------------------------------------------------------
// Summary data
// ---------------------------------------------------------------------------

type summaryData struct {
	results map[string]*steps.StepResult
	order   []string
}

// ---------------------------------------------------------------------------
// Subway model (pure state + view, no bubbletea dependency)
// ---------------------------------------------------------------------------

type subwayModel struct {
	stations []station
	summary  *summaryData
	warning  string
}

func newSubwayModel(stepNames []string) subwayModel {
	stations := make([]station, len(stepNames))
	for i, name := range stepNames {
		stations[i] = station{name: name, status: stationPending}
	}
	return subwayModel{stations: stations}
}

// applyStart transitions a station to running.
func (m subwayModel) applyStart(name string) subwayModel {
	next := m.clone()
	for i := range next.stations {
		if next.stations[i].name == name {
			next.stations[i].status = stationRunning
			break
		}
	}
	return next
}

// applyResult transitions a station to complete with its result.
func (m subwayModel) applyResult(name string, result *steps.StepResult) subwayModel {
	next := m.clone()
	for i := range next.stations {
		if next.stations[i].name == name {
			next.stations[i].status = stationComplete
			next.stations[i].result = result
			break
		}
	}
	return next
}

// applyError transitions a station to failed with its error.
func (m subwayModel) applyError(name string, err error) subwayModel {
	next := m.clone()
	for i := range next.stations {
		if next.stations[i].name == name {
			next.stations[i].status = stationFailed
			next.stations[i].err = err
			break
		}
	}
	return next
}

// applySummary attaches summary data.
func (m subwayModel) applySummary(results map[string]*steps.StepResult, order []string) subwayModel {
	next := m.clone()
	next.summary = &summaryData{results: results, order: order}
	return next
}

// applyWarning sets the warning message.
func (m subwayModel) applyWarning(msg string) subwayModel {
	next := m.clone()
	next.warning = msg
	return next
}

func (m subwayModel) clone() subwayModel {
	stations := make([]station, len(m.stations))
	copy(stations, m.stations)
	return subwayModel{
		stations: stations,
		summary:  m.summary,
		warning:  m.warning,
	}
}

// ---------------------------------------------------------------------------
// Lipgloss styles for the subway renderer
// ---------------------------------------------------------------------------

var (
	subwayGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	subwayYellow = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	subwayRed    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	subwayGray   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	subwayBold   = lipgloss.NewStyle().Bold(true)
	subwayDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	subwayTrackGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	subwayTrackYellow = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	subwayTrackRed    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	subwayTrackGray   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
)

// ---------------------------------------------------------------------------
// renderView — the main rendering function
// ---------------------------------------------------------------------------

func (m subwayModel) renderView() string {
	var sb strings.Builder

	// Warning banner at top
	if m.warning != "" {
		sb.WriteString(styleWarning.Render("⚠  "+m.warning) + "\n\n")
	}

	for i, st := range m.stations {
		// Station line
		icon, nameLine := m.renderStation(st)
		sb.WriteString(icon + "━━ " + nameLine + "\n")

		// Detail fields below completed stations
		if st.status == stationComplete && st.result != nil {
			trackStyle := subwayTrackGreen
			track := trackStyle.Render("┃")

			for _, f := range st.result.Fields {
				val := MaskField(f.Value, f.Sensitive)
				sb.WriteString(track + "    " + styleLabel.Render(f.Label) + "  " + styleValue.Render(val) + "\n")
			}

			// Sub-steps as branch stations
			for _, sub := range st.result.SubSteps {
				var marker string
				if sub.Status == steps.StatusPass {
					marker = subwayGreen.Render("◉")
				} else {
					marker = subwayRed.Render("✗")
				}
				line := track + "    " + marker + "─ " + sub.Name + " (" + sub.Duration.String() + ")"
				if sub.Error != "" {
					line += "  " + subwayRed.Render(sub.Error)
				}
				sb.WriteString(line + "\n")
			}
		}

		// Error details below failed stations
		if st.status == stationFailed && st.err != nil {
			trackStyle := subwayTrackRed
			track := trackStyle.Render("┃")

			var stepErr *steps.StepError
			if errors.As(st.err, &stepErr) {
				if stepErr.Code != "" {
					sb.WriteString(track + "    " + styleLabel.Render("Code") + "  " + styleValue.Render(stepErr.Code) + "\n")
				}
				sb.WriteString(track + "    " + styleLabel.Render("Error") + "  " + styleValue.Render(stepErr.Err.Error()) + "\n")
				if stepErr.Hint != "" {
					sb.WriteString(track + "    " + styleHint.Render("Hint: "+stepErr.Hint) + "\n")
				}
			} else {
				sb.WriteString(track + "    " + styleLabel.Render("Error") + "  " + styleValue.Render(st.err.Error()) + "\n")
			}
		}

		// Track connector between stations
		if i < len(m.stations)-1 {
			trackStyle := m.trackStyleFor(st.status)
			sb.WriteString(trackStyle.Render("┃") + "\n")
		}
	}

	// Summary section
	if m.summary != nil {
		sb.WriteString("\n")
		sb.WriteString(subwayBold.Render("Summary") + "\n")

		var totalDuration time.Duration
		for _, key := range m.summary.order {
			result, ok := m.summary.results[key]
			if !ok {
				continue
			}
			totalDuration += result.Duration
			sb.WriteString("  " + subwayGreen.Render("✓") + "  " + styleLabel.Render(result.Title) + "  " + subwayDim.Render(result.Duration.String()) + "\n")
		}
		sb.WriteString("\n  " + subwayBold.Render("Total: "+totalDuration.String()) + "\n")
	}

	return sb.String()
}

// renderStation returns the icon and name line for a station.
func (m subwayModel) renderStation(st station) (string, string) {
	switch st.status {
	case stationComplete:
		dur := ""
		if st.result != nil {
			dur = " ··· " + subwayDim.Render(st.result.Duration.String())
		}
		return subwayGreen.Render("◉"), subwayGreen.Render(st.name) + dur
	case stationRunning:
		return subwayYellow.Render("◎"), subwayYellow.Render(st.name) + " " + subwayDim.Render("running...")
	case stationFailed:
		return subwayRed.Render("✗"), subwayRed.Render(st.name) + " " + subwayRed.Render("FAILED")
	default:
		return subwayGray.Render("○"), subwayGray.Render(st.name)
	}
}

// trackStyleFor returns the lipgloss style for the track connector below a station.
func (m subwayModel) trackStyleFor(status stationStatus) lipgloss.Style {
	switch status {
	case stationComplete:
		return subwayTrackGreen
	case stationRunning:
		return subwayTrackYellow
	case stationFailed:
		return subwayTrackRed
	default:
		return subwayTrackGray
	}
}

// ---------------------------------------------------------------------------
// Bubbletea message types
// ---------------------------------------------------------------------------

type msgStepStart struct{ name string }
type msgStepResult struct {
	name   string
	result *steps.StepResult
}
type msgStepError struct {
	name string
	err  error
}
type msgSummary struct {
	results map[string]*steps.StepResult
	order   []string
}
type msgWarning struct{ msg string }
type msgQuit struct{}

// ---------------------------------------------------------------------------
// Bubbletea model wrapping subwayModel
// ---------------------------------------------------------------------------

type teaModel struct {
	subway subwayModel
	ch     <-chan tea.Msg
}

func waitForMsg(ch <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return msgQuit{}
		}
		return msg
	}
}

func (m teaModel) Init() tea.Cmd {
	return waitForMsg(m.ch)
}

func (m teaModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case msgStepStart:
		m.subway = m.subway.applyStart(msg.name)
		return m, waitForMsg(m.ch)
	case msgStepResult:
		m.subway = m.subway.applyResult(msg.name, msg.result)
		return m, waitForMsg(m.ch)
	case msgStepError:
		m.subway = m.subway.applyError(msg.name, msg.err)
		return m, waitForMsg(m.ch)
	case msgSummary:
		m.subway = m.subway.applySummary(msg.results, msg.order)
		return m, waitForMsg(m.ch)
	case msgWarning:
		m.subway = m.subway.applyWarning(msg.msg)
		return m, waitForMsg(m.ch)
	case msgQuit:
		return m, tea.Quit
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m teaModel) View() string {
	return m.subway.renderView()
}

// ---------------------------------------------------------------------------
// SubwayRenderer — implements the Renderer interface
// ---------------------------------------------------------------------------

// SubwayRenderer is a live TUI renderer that displays steps as subway stations.
type SubwayRenderer struct {
	ch   chan tea.Msg
	prog *tea.Program
	done chan struct{}
	once sync.Once
}

// NewSubwayRenderer creates a SubwayRenderer for the given step names.
func NewSubwayRenderer(stepNames []string) *SubwayRenderer {
	ch := make(chan tea.Msg, 16)
	model := teaModel{
		subway: newSubwayModel(stepNames),
		ch:     ch,
	}
	prog := tea.NewProgram(model)
	return &SubwayRenderer{
		ch:   ch,
		prog: prog,
		done: make(chan struct{}),
	}
}

// Start launches the bubbletea program in a goroutine.
func (r *SubwayRenderer) Start() {
	go func() {
		defer close(r.done)
		_, _ = r.prog.Run()
	}()
}

// Stop closes the message channel and waits for the program to exit.
func (r *SubwayRenderer) Stop() {
	r.once.Do(func() {
		close(r.ch)
	})
	<-r.done
}

// RenderStepStart sends a step-start message to the TUI.
func (r *SubwayRenderer) RenderStepStart(name string) {
	r.ch <- msgStepStart{name: name}
}

// RenderStepResult sends a step-result message to the TUI.
func (r *SubwayRenderer) RenderStepResult(name string, result *steps.StepResult) {
	r.ch <- msgStepResult{name: name, result: result}
}

// RenderStepError sends a step-error message to the TUI.
func (r *SubwayRenderer) RenderStepError(name string, err error) {
	r.ch <- msgStepError{name: name, err: err}
}

// RenderSummary sends a summary message to the TUI.
func (r *SubwayRenderer) RenderSummary(results map[string]*steps.StepResult, order []string) {
	r.ch <- msgSummary{results: results, order: order}
}

// RenderWarning sends a warning message to the TUI.
func (r *SubwayRenderer) RenderWarning(msg string) {
	r.ch <- msgWarning{msg: msg}
}

// Verify interface compliance at compile time.
var _ Renderer = (*SubwayRenderer)(nil)
