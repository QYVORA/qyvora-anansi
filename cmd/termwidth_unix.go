//go:build !windows

package cmd

import (
	"os"

	"golang.org/x/sys/unix"
)

// terminalWidth returns the live column count of the terminal attached to
// stdout, or 0 when stdout is not a terminal or the size cannot be read.
func terminalWidth() int {
	if !writerIsTerminal(os.Stdout) {
		return 0
	}
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0
	}
	return int(ws.Col)
}
