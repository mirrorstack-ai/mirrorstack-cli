// Package browser opens URLs in the user's default web browser.
//
// Best-effort: callers should ALWAYS print the URL alongside the open
// attempt so the user can copy-paste if auto-open fails (headless env,
// SSH session, browser crashed, etc.).
package browser

import (
	"os/exec"
	"runtime"
)

// Open tries to open url in the user's default browser. Returns nil on
// success (the OS handler accepted the request — not necessarily that
// the browser actually loaded the page).
func Open(url string) error {
	cmd, args := openCommand(url)
	return exec.Command(cmd, args...).Start()
}

func openCommand(url string) (string, []string) {
	switch runtime.GOOS {
	case "darwin":
		return "open", []string{url}
	case "windows":
		// rundll32 is the historical low-friction way to invoke the
		// default protocol handler without needing a shell.
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		return "xdg-open", []string{url}
	}
}
