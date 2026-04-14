package browser

import (
	"os/exec"
	"runtime"
)

func Open(url string) {
	cmd, args := browserCommand(url)
	if cmd == "" {
		return
	}
	exec.Command(cmd, args...).Start()
}

func browserCommand(url string) (string, []string) {
	switch runtime.GOOS {
	case "darwin":
		return "open", []string{url}
	case "linux":
		return "xdg-open", []string{url}
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		return "", nil
	}
}
