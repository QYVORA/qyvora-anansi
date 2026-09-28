//go:build !windows

package cmd

import (
	"io"
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

// writerIsTerminal reports whether w is an interactive terminal.
//
// This asks whether a person is watching, so it uses a character-device test
// rather than a full isatty: it only ever decides whether to emit ANSI styling
// and truncate to the measured width, and a false answer there is cosmetic
// rather than destructive.
func writerIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
