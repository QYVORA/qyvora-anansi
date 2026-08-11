//go:build windows

package cmd

// terminalWidth reports the live column count of the terminal attached to
// stdout.  Windows terminals are not queried; a zero width makes the HUD fall
// back to its default width.
func terminalWidth() int {
	return 0
}
