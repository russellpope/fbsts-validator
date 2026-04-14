package render

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pure-experimental/rp-fbstsvalidator/internal/steps"
)

// containsStr is a test helper that checks if s contains substr.
func containsStr(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestNewSubwayModel(t *testing.T) {
	names := []string{"OktaDeviceAuth", "TokenDecode", "STSAssume", "S3Validate"}
	m := newSubwayModel(names)

	if len(m.stations) != 4 {
		t.Errorf("expected 4 stations, got %d", len(m.stations))
	}

	for i, st := range m.stations {
		if st.name != names[i] {
			t.Errorf("station %d: expected name %q, got %q", i, names[i], st.name)
		}
		if st.status != stationPending {
			t.Errorf("station %d: expected pending status, got %d", i, st.status)
		}
		if st.result != nil {
			t.Errorf("station %d: expected nil result", i)
		}
		if st.err != nil {
			t.Errorf("station %d: expected nil error", i)
		}
	}
}

func TestStationTransitions(t *testing.T) {
	names := []string{"OktaDeviceAuth", "TokenDecode", "STSAssume", "S3Validate"}
	m := newSubwayModel(names)

	// Start first step -> running
	m = m.applyStart("OktaDeviceAuth")
	if m.stations[0].status != stationRunning {
		t.Errorf("expected OktaDeviceAuth to be running, got %d", m.stations[0].status)
	}

	// Complete first step -> complete with result
	result := &steps.StepResult{
		Title:    "Okta Device Auth",
		Duration: 5 * time.Second,
	}
	m = m.applyResult("OktaDeviceAuth", result)
	if m.stations[0].status != stationComplete {
		t.Errorf("expected OktaDeviceAuth to be complete, got %d", m.stations[0].status)
	}
	if m.stations[0].result != result {
		t.Error("expected result to be stored on station")
	}

	// Start second step -> running
	m = m.applyStart("TokenDecode")
	if m.stations[1].status != stationRunning {
		t.Errorf("expected TokenDecode to be running, got %d", m.stations[1].status)
	}

	// Fail second step -> failed with error
	testErr := fmt.Errorf("decode failed")
	m = m.applyError("TokenDecode", testErr)
	if m.stations[1].status != stationFailed {
		t.Errorf("expected TokenDecode to be failed, got %d", m.stations[1].status)
	}
	if m.stations[1].err != testErr {
		t.Error("expected error to be stored on station")
	}

	// Remaining stations stay pending
	if m.stations[2].status != stationPending {
		t.Errorf("expected STSAssume to remain pending, got %d", m.stations[2].status)
	}
	if m.stations[3].status != stationPending {
		t.Errorf("expected S3Validate to remain pending, got %d", m.stations[3].status)
	}
}

func TestSubwayView(t *testing.T) {
	names := []string{"OktaDeviceAuth", "TokenDecode", "STSAssume", "S3Validate"}
	m := newSubwayModel(names)

	view := m.renderView()

	// All stations should appear as pending with the ○ marker
	for _, name := range names {
		if !containsStr(view, name) {
			t.Errorf("view should contain step name %q", name)
		}
	}
	if !containsStr(view, "○") {
		t.Error("view should contain pending marker ○")
	}
}

func TestSubwayViewWithSubSteps(t *testing.T) {
	names := []string{"S3Validate"}
	m := newSubwayModel(names)

	result := &steps.StepResult{
		Title: "S3 Validate",
		SubSteps: []steps.SubStep{
			{Name: "ListBuckets", Status: steps.StatusPass, Duration: 30 * time.Millisecond},
			{Name: "PutObject", Status: steps.StatusFail, Duration: 100 * time.Millisecond, Error: "403 Forbidden"},
		},
		Duration: 130 * time.Millisecond,
	}

	m = m.applyStart("S3Validate")
	m = m.applyResult("S3Validate", result)

	view := m.renderView()

	if !containsStr(view, "ListBuckets") {
		t.Error("view should contain sub-step name ListBuckets")
	}
	if !containsStr(view, "PutObject") {
		t.Error("view should contain sub-step name PutObject")
	}
}

func TestSubwaySummaryView(t *testing.T) {
	names := []string{"OktaDeviceAuth", "TokenDecode"}
	m := newSubwayModel(names)

	r1 := &steps.StepResult{Title: "Okta Device Auth", Duration: 5 * time.Second}
	r2 := &steps.StepResult{Title: "Token Decode", Duration: 2 * time.Millisecond}

	m = m.applyStart("OktaDeviceAuth")
	m = m.applyResult("OktaDeviceAuth", r1)
	m = m.applyStart("TokenDecode")
	m = m.applyResult("TokenDecode", r2)

	results := map[string]*steps.StepResult{
		"OktaDeviceAuth": r1,
		"TokenDecode":    r2,
	}
	order := []string{"OktaDeviceAuth", "TokenDecode"}
	m = m.applySummary(results, order)

	view := m.renderView()

	if !containsStr(view, "Summary") {
		t.Error("view should contain Summary heading")
	}
	if !containsStr(view, "Okta Device Auth") {
		t.Error("summary should contain step title Okta Device Auth")
	}
	if !containsStr(view, "Token Decode") {
		t.Error("summary should contain step title Token Decode")
	}
}
