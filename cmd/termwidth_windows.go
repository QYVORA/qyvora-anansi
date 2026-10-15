//go:build ignore

// Disabled together with the TUI (cmd/tui.go); the terminal-width helper was
// only used by the interactive interface.

package cmd

// terminalWidth reports the live column count of the terminal attached to
// stdout.  Windows terminals are not queried; a zero width makes the HUD fall
// back to its default width.
func terminalWidth() int {
	return 0
}
