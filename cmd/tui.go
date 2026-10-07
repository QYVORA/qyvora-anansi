package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-anansi/internal/version"
	"github.com/QYVORA/qyvora-tui"
)

// runTUI starts the interactive terminal application.
//
// The TUI is a presentation layer over the same command tree the one-shot CLI
// exposes. Commands run in-process through the same execution entry point the
// one-shot path uses, and the interface renders from the structured event
// stream, so it never parses human-readable output.
//
// The root command is passed in rather than reached for directly: the root's own
// default action calls this function, so naming the root from here would be an
// initialisation cycle.
func runTUI(root *cobra.Command, ctx context.Context) error {
	// A TUI needs a terminal. When stdout is redirected, or when the process is
	// driven by something that is not a person, fall through to ordinary
	// behaviour. Drawing a full-screen interface into a pipe would fill it with
	// escape codes and destroy the machine-readable output the tool exists to
	// produce.
	if !tui.IsInteractive(os.Stdout) {
		return root.Help()
	}

	// A machine event destination and the interface are contradictory: one
	// screen cannot hand the same bytes to a renderer and to a file. The
	// destination used to be ignored in silence, so a bare
	// `--events out.jsonl` opened the session and wrote no file.
	//
	// The flag has to have been *asked for*, not merely be set. This tool's
	// --events may default to a real destination so the stream is always on, and
	// testing the value alone would refuse every ordinary interactive run.
	if root.Flags().Changed("events") && !eventsDisabled(flagEvents) {
		return &usageError{fmt.Errorf("cannot open the interactive session with a machine event destination (--events); the session transcript is already its event stream. Run a command for machine output, or drop --events to use the session.")}
	}

	runner := &tui.InProcessRunner{
		ToolName: "anansi",
		Execute:  ExecuteArgsContext,
		Meta:     tuiCommands(root),
	}

	code, err := tui.Run(tui.Config{
		Title:   "QYVORA / ANANSI",
		Version: version.String(),
		Runner:  runner,
		Out:     os.Stdout,
	})
	if err != nil {
		if tui.IsNotInteractive(err) {
			return root.Help()
		}
		return err
	}
	if code != 0 {
		return &exitStatusError{code: code}
	}
	return nil
}

// commandTUI returns the explicit form of the interactive command, so the TUI
// can be started without relying on the bare invocation.
//
// "console" is kept as an alias: it used to name a separate hand-written
// console, and existing invocations and documentation use it.
func commandTUI() *cobra.Command {
	return &cobra.Command{
		Use:     "tui",
		Aliases: []string{"console"},
		Short:   "start the interactive terminal application",
		Long: "Start the QYVORA interactive terminal application.\n\n" +
			"Commands are entered at the prompt and executed through the same engine as\n" +
			"the one-shot CLI, with the structured event stream rendered in the session.\n" +
			"Ctrl+C stops the running command; Ctrl+D leaves.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTUI(cmd.Root(), cmd.Context())
		},
	}
}

// exitStatusError carries a non-zero exit code out of the TUI so the process
// still reports the status of the last command that ran.
type exitStatusError struct{ code int }

func (e *exitStatusError) Error() string {
	return fmt.Sprintf("last command exited with status %d", e.code)
}

// tuiCommands derives completion metadata from the live command tree, so
// completion cannot drift away from the commands that actually exist.
// Per PROMPT1.md: Uses the shared CobraCommands() adapter to extract full
// metadata (flags, examples, groups, etc.) from the Cobra tree.
func tuiCommands(root *cobra.Command) []tui.Command {
	return tui.CobraCommands(root)
}
