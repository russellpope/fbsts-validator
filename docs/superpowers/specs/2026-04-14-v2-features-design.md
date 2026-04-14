# fbsts v2 Features -- Design Spec

## Overview

Three enhancements to the FlashBlade STS Validator tool:

1. **Subway-Map Renderer** -- a live TUI renderer that displays the validation flow as a vertical metro map with stations filling in as steps complete
2. **Browser Auto-Open** -- automatically opens the Okta verification URL in the user's default browser during device code auth
3. **Binary Releases** -- GoReleaser config and GitHub Actions workflow for automated cross-platform releases

## Feature 1: Subway-Map Renderer

### Architecture

A new `SubwayRenderer` implementing the existing `Renderer` interface (`internal/render/renderer.go`). Uses `charmbracelet/bubbletea` for a live-updating TUI with the `lipgloss` styles already in the project.

### Visual Design

Vertical metro line with each pipeline step as a station. Three station states:

```
◉━━ Step Name ··· 230ms        (complete — green)
◎━━ Step Name running...       (active — yellow, animated)
○━━ Step Name                  (pending — dim gray)
✗━━ Step Name ··· FAILED       (failed — red)
```

Completed stations reveal detail fields indented below:

```
◉━━ Okta Device Auth ··· 5.2s
┃    User Code:    ABCD-1234
┃    ID Token:     eyJhbG...<masked>...kF9xQ
┃
◉━━ Token Decode ··· 1ms
┃    Subject:      user@example.com
┃    Groups:       [admin, users]
┃
◎━━ STS Assume running...
┃
○━━ S3 Validate
```

The S3Validate step expands into sub-stations on an indented branch line:

```
◎━━ S3 Validate
┃    ◉─ ListBuckets  200 OK (45ms)
┃    ◉─ PutObject    200 OK (80ms)
┃    ◎─ GetObject    running...
┃    ○─ DeleteObject
```

Failed stations show the error and diagnostic hint:

```
✗━━ STS Assume ··· FAILED
┃    Error:   AccessDenied
┃    Hint:    Check that the role's trust policy includes your OIDC provider
```

### Bubbletea Model

```go
type SubwayModel struct {
    steps     []stationState      // ordered list of stations
    activeIdx int                 // currently running step (-1 if none)
    done      bool                // flow complete
    demoPace  time.Duration       // 0 = no pacing, 800ms in demo mode
    width     int                 // terminal width for layout
}

type stationState struct {
    name      string
    status    Status              // pending, running, complete, failed
    result    *steps.StepResult   // nil until complete
    err       error               // nil unless failed
    subSteps  []subStationState   // for S3Validate branch line
}
```

The model receives messages from the `SubwayRenderer` methods via a channel. `RenderStepStart`, `RenderStepResult`, and `RenderStepError` send typed messages that the bubbletea `Update` function processes to transition station states.

### Masking

Uses the same `render.MaskField` function as `PanelRenderer`. Detail fields that have `Sensitive: true` are masked before display.

### Demo Mode

When `--demo` is set:
- Renderer is set to `subway`
- An 800ms pause is inserted between step completions (after a step's result is rendered, before the next step's `RenderStepStart` message)
- The pause is handled by the runner, not the renderer — the runner checks if demo pacing is enabled and sleeps between steps

### CLI Flags

```
--renderer panel|subway   Renderer style (default: panel)
--demo                    Enable demo mode: subway renderer + 800ms inter-step pacing
```

When `--demo` is passed, it implies `--renderer subway`. If both are passed, `--renderer` value is ignored in favor of subway.

### Files

```
internal/render/subway.go       — SubwayRenderer + bubbletea model
internal/render/subway_test.go  — tests for station state transitions
```

### New Dependency

`github.com/charmbracelet/bubbletea` — already in the Charm ecosystem alongside lipgloss.

### Changes to Existing Files

- `cmd/fbsts/main.go` — add `--renderer` and `--demo` flags, select renderer based on flags
- `internal/runner/runner.go` — add demo pacing support (sleep between steps when enabled)
- `internal/render/renderer.go` — no interface changes needed

## Feature 2: Browser Auto-Open

### Implementation

A small utility package `internal/browser/` with a single function:

```go
// Open attempts to open the given URL in the user's default browser.
// It is non-blocking and silently ignores failures.
func Open(url string) {
    var cmd string
    var args []string

    switch runtime.GOOS {
    case "darwin":
        cmd = "open"
        args = []string{url}
    case "linux":
        cmd = "xdg-open"
        args = []string{url}
    case "windows":
        cmd = "rundll32"
        args = []string{"url.dll,FileProtocolHandler", url}
    default:
        return
    }

    exec.Command(cmd, args...).Start() // fire and forget
}
```

### Integration

In `internal/steps/okta_device_auth.go`, after printing the verification URL to stdout, call `browser.Open(deviceAuth.VerificationURIComplete)`.

### Behavior

- Non-blocking: the `Start()` call launches the process and returns immediately
- Silent failure: if the command doesn't exist or fails, the URL is already printed to stdout
- No CLI flag: works automatically when a browser is available, no-ops otherwise
- Works in SSH/headless: `open`/`xdg-open` will fail, user sees the URL in terminal as before

### Files

```
internal/browser/open.go       — Open(url) function
internal/browser/open_test.go  — test platform detection logic
```

## Feature 3: Binary Releases

### GoReleaser Config

`.goreleaser.yaml`:

```yaml
version: 2

builds:
  - id: fbsts
    main: ./cmd/fbsts
    binary: fbsts
    env:
      - CGO_ENABLED=0
    goos:
      - darwin
      - linux
      - windows
    goarch:
      - amd64
      - arm64
    ignore:
      - goos: windows
        goarch: arm64
    ldflags:
      - -s -w -X main.version={{.Version}}

archives:
  - id: fbsts
    builds:
      - fbsts
    format: tar.gz
    format_overrides:
      - goos: windows
        format: zip
    name_template: "fbsts_{{ .Version }}_{{ .Os }}_{{ .Arch }}"

checksum:
  name_template: "checksums.txt"

changelog:
  sort: asc
  filters:
    exclude:
      - "^docs:"
      - "^test:"
      - "^chore:"
```

### GitHub Actions Workflow

`.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - "v*"

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - name: Run tests
        run: go test ./... -v -timeout 60s

      - uses: goreleaser/goreleaser-action@v6
        with:
          version: latest
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Build Targets

| OS | Arch | Archive Format |
|----|------|----------------|
| darwin | amd64 | tar.gz |
| darwin | arm64 | tar.gz |
| linux | amd64 | tar.gz |
| linux | arm64 | tar.gz |
| windows | amd64 | zip |

### Version Injection

The existing `var version = "dev"` in `cmd/fbsts/main.go` is overwritten at build time via:
```
-ldflags "-s -w -X main.version={{.Version}}"
```

No code changes needed — goreleaser handles this automatically.

### Release Workflow

```
git tag v0.1.0
git push origin v0.1.0
→ GitHub Actions triggers
→ Tests run
→ GoReleaser builds 5 binaries
→ Uploads to GitHub Releases with checksums
```

### Files

```
.goreleaser.yaml                    — goreleaser configuration
.github/workflows/release.yml      — GitHub Actions release workflow
```
