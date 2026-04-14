package browser

import (
	"runtime"
	"testing"
)

func TestBrowserCommandForPlatform(t *testing.T) {
	cmd, args := browserCommand("https://example.com/activate?code=ABCD")

	switch runtime.GOOS {
	case "darwin":
		if cmd != "open" {
			t.Errorf("on darwin expected 'open', got %q", cmd)
		}
		if len(args) != 1 || args[0] != "https://example.com/activate?code=ABCD" {
			t.Errorf("unexpected args: %v", args)
		}
	case "linux":
		if cmd != "xdg-open" {
			t.Errorf("on linux expected 'xdg-open', got %q", cmd)
		}
		if len(args) != 1 || args[0] != "https://example.com/activate?code=ABCD" {
			t.Errorf("unexpected args: %v", args)
		}
	case "windows":
		if cmd != "rundll32" {
			t.Errorf("on windows expected 'rundll32', got %q", cmd)
		}
	default:
		if cmd != "" {
			t.Errorf("on unsupported OS expected empty cmd, got %q", cmd)
		}
	}
}

func TestBrowserCommandEmpty(t *testing.T) {
	cmd, _ := browserCommand("")
	_ = cmd // just verify no panic
}
