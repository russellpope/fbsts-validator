package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var (
	styleKey    = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))  // cyan
	styleStr    = lipgloss.NewStyle().Foreground(lipgloss.Color("10")) // green
	styleNum    = lipgloss.NewStyle().Foreground(lipgloss.Color("11")) // yellow
	styleBool   = lipgloss.NewStyle().Foreground(lipgloss.Color("13")) // magenta
	styleNull   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))  // dim
	styleHeader = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
)

func newDecodeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "decode <file>",
		Short: "Decode and display a JWT from a file",
		Long:  "Reads a JWT from a file, decodes the header and payload, and displays them as formatted JSON. No signature verification is performed.",
		Args:  cobra.ExactArgs(1),
		RunE:  runDecode,
	}
}

func runDecode(cmd *cobra.Command, args []string) error {
	raw, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("reading %s: %w", args[0], err)
	}

	token := strings.TrimSpace(string(raw))
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT: expected 3 dot-separated parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("decoding JWT header: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decoding JWT payload: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("parsing JWT header JSON: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("parsing JWT payload JSON: %w", err)
	}

	fmt.Println(styleHeader.Render("Header"))
	fmt.Println(renderJSON(header, 0))
	fmt.Println()
	fmt.Println(styleHeader.Render("Payload"))
	fmt.Println(renderJSON(payload, 0))

	return nil
}

// renderJSON renders a parsed JSON value with syntax highlighting.
func renderJSON(v interface{}, indent int) string {
	prefix := strings.Repeat("  ", indent)

	switch val := v.(type) {
	case map[string]interface{}:
		if len(val) == 0 {
			return "{}"
		}
		keys := sortedKeys(val)
		var lines []string
		lines = append(lines, "{")
		for i, key := range keys {
			comma := ","
			if i == len(keys)-1 {
				comma = ""
			}
			rendered := renderJSON(val[key], indent+1)
			lines = append(lines, fmt.Sprintf("%s  %s: %s%s",
				prefix,
				styleKey.Render(fmt.Sprintf("%q", key)),
				rendered,
				comma,
			))
		}
		lines = append(lines, prefix+"}")
		return strings.Join(lines, "\n")

	case []interface{}:
		if len(val) == 0 {
			return "[]"
		}
		// Short arrays of simple values render inline.
		if isSimpleArray(val) && len(val) <= 5 {
			items := make([]string, len(val))
			for i, item := range val {
				items[i] = renderJSON(item, 0)
			}
			return "[" + strings.Join(items, ", ") + "]"
		}
		var lines []string
		lines = append(lines, "[")
		for i, item := range val {
			comma := ","
			if i == len(val)-1 {
				comma = ""
			}
			lines = append(lines, fmt.Sprintf("%s  %s%s", prefix, renderJSON(item, indent+1), comma))
		}
		lines = append(lines, prefix+"]")
		return strings.Join(lines, "\n")

	case string:
		return styleStr.Render(fmt.Sprintf("%q", val))

	case float64:
		if val == float64(int64(val)) {
			return styleNum.Render(fmt.Sprintf("%d", int64(val)))
		}
		return styleNum.Render(fmt.Sprintf("%g", val))

	case bool:
		return styleBool.Render(fmt.Sprintf("%t", val))

	case nil:
		return styleNull.Render("null")

	default:
		return fmt.Sprintf("%v", val)
	}
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isSimpleArray(arr []interface{}) bool {
	for _, item := range arr {
		switch item.(type) {
		case map[string]interface{}, []interface{}:
			return false
		}
	}
	return true
}
