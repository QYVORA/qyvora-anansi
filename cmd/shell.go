package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Shell integration: operators can run normal Linux commands without leaving
// the console, mirroring Metasploit's `shell` command and bettercap's `!`
// prefix. The console's own prompt returns once the command (or interactive
// shell session) ends. A session-level working directory is tracked so `cd`
// navigation persists across commands, exactly as in a real shell.
//
//   - `!<command>`   run one system command and return to the prompt
//   - `shell [cmd]`  drop into an interactive /bin/sh, or run a command
//   - `cd <dir>`     change the console working directory
//   - `pwd`          print the console working directory

// shellKind classifies a console line so the REPL can skip interactive
// niceties (spinners, prompt refreshers) that would fight a live child shell.
func shellKind(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	switch strings.ToLower(fields[0]) {
	case "cd", "pwd":
		return "shell"
	case "shell":
		if len(fields) == 1 {
			return "interactive"
		}
		return "shell"
	}
	if strings.HasPrefix(fields[0], "!") {
		return "shell"
	}
	return ""
}

// isInteractiveShell reports whether the line drops the operator into a live
// child shell that owns the terminal (bare `shell`).
func isInteractiveShell(line string) bool {
	return shellKind(line) == "interactive"
}

// runShell executes one system command through the shell from the session
// working directory. A non-zero exit status is not treated as a console error
// (the command's own stderr is already visible); only a genuine execution
// failure (missing shell, permissions) surfaces.
func (s *consoleSession) runShell(cmdline string) error {
	cmd := exec.Command("/bin/sh", "-c", cmdline)
	cmd.Dir = s.cwd
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return nil
	}
	return fmt.Errorf("shell: %w", err)
}

// runInteractiveShell drops the operator into a live /bin/sh bound to the
// console working directory. When the shell exits, control returns to the
// console regardless of the shell's exit status.
func (s *consoleSession) runInteractiveShell() error {
	cmd := exec.Command("/bin/sh")
	cmd.Dir = s.cwd
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Fprintln(s.out, "  "+s.ui.paint(cpDim, "dropping into a shell — type 'exit' to return to the console"))
	_ = cmd.Run()
	return nil
}

// changeDir updates the session working directory. `cd` with no argument (or
// with "~") returns to the user's home directory, matching shell behaviour.
// The process working directory is never changed; only the console session's
// logical cwd moves, so all later shell commands inherit it via cmd.Dir.
func (s *consoleSession) changeDir(path string) error {
	if path == "" || path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cd: cannot resolve home directory: %w", err)
		}
		path = home
	} else if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(s.cwd, path)
	}
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cd: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cd: %s is not a directory", path)
	}
	s.cwd = path
	return nil
}
