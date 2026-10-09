package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-anansi/internal/output"
	"github.com/QYVORA/qyvora-anansi/internal/version"
)

func TestHasModule(t *testing.T) {
	flagModules = []string{"discovery", " probe ", "TLS"}
	defer func() { flagModules = nil }()

	tests := []struct {
		name string
		want bool
	}{
		{"discovery", true},
		{"probe", true},
		{"tls", true},
		{"TLS", true},
		{"paths", false},
		{"tech", false},
	}
	for _, tt := range tests {
		if got := hasModule(tt.name); got != tt.want {
			t.Errorf("hasModule(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestDedupeFindings(t *testing.T) {
	in := []output.Finding{
		{Title: "XSS", AffectedAsset: "a.com"},
		{Title: "XSS", AffectedAsset: "a.com"},
		{Title: "XSS", AffectedAsset: "b.com"},
		{Title: "SQLi", AffectedAsset: "a.com"},
	}
	got := dedupeFindings(in)
	if len(got) != 3 {
		t.Fatalf("dedupeFindings = %d findings, want 3", len(got))
	}
}

func TestVersionFlagPrintsVersion(t *testing.T) {
	old := version.Version
	version.Version = "test-1.2.3"
	defer func() { version.Version = old }()

	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute --version: %v", err)
	}
	if got := buf.String(); got != "test-1.2.3\n" {
		t.Errorf("--version printed %q, want %q", got, "test-1.2.3\n")
	}
}

func TestVersionSubcommandPrintsVersion(t *testing.T) {
	old := version.Version
	version.Version = "v9.9.9-rc1"
	defer func() { version.Version = old }()

	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute version subcommand: %v", err)
	}
	if got := buf.String(); !strings.Contains(got, "anansi v9.9.9-rc1\n") {
		t.Errorf("version subcommand printed %q, want to contain %q", got, "anansi v9.9.9-rc1\n")
	}
	if got := buf.String(); !strings.Contains(got, "support:    qyvorasec@gmail.com") {
		t.Errorf("version subcommand printed %q, want contact details", got)
	}
}

// TestVersionSubcommandJSONOutput verifies the shared QYVORA output contract:
// `-o json` on the version verb emits a machine-readable object, and an
// unsupported format is rejected as a usage error.
func TestVersionSubcommandJSONOutput(t *testing.T) {
	old := version.Version
	version.Version = "v9.9.9-rc1"
	defer func() { version.Version = old }()

	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"version", "-o", "json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute version -o json: %v", err)
	}
	var parsed map[string]string
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("version -o json emitted invalid JSON %q: %v", buf.String(), err)
	}
	if parsed["framework"] != "anansi" || parsed["version"] != "v9.9.9-rc1" {
		t.Errorf("version -o json = %v, want framework=anansi version=v9.9.9-rc1", parsed)
	}

	root = newRootCmd()
	root.SetOut(&buf)
	buf.Reset()
	root.SetArgs([]string{"version", "-o", "yaml"})
	err := root.Execute()
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Errorf("version -o yaml error = %v, want usageError (exit 2)", err)
	}
}

func TestRunScanRejectsIPTarget(t *testing.T) {
	err := runScan(&cobra.Command{}, []string{"192.168.1.1"})
	if err == nil {
		t.Fatal("expected error for IP target, got nil")
	}
}

func TestExecuteTreatsTargetAsPositionalArg(t *testing.T) {
	// Guards against cobra "unknown command" regressions: the root command
	// has subcommands but must still accept a bare domain target.
	root := newRootCmd()
	if err := root.Flags().Set("version", "false"); err != nil {
		t.Fatalf("resetting version flag: %v", err)
	}
	root.SetArgs([]string{"192.168.1.1"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected IP rejection error, got nil")
	}
	if strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("target was treated as a subcommand: %v", err)
	}
	if !strings.Contains(err.Error(), "not an IP") {
		t.Fatalf("expected IP validation error, got: %v", err)
	}
}

func TestRunScanRejectsMalformedDomain(t *testing.T) {
	for _, target := range []string{"example..com", "https://", ".", "a..b"} {
		if err := runScan(&cobra.Command{}, []string{target}); err == nil {
			t.Errorf("expected error for target %q, got nil", target)
		}
	}
}

func TestScanSubcommandRejectsMissingTarget(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"scan"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "1 arg") {
		t.Errorf("scan without target: got %v, want arg-count error", err)
	}
}

func TestScanSubcommandRejectsIPTarget(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"scan", "192.168.1.1"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "not an IP") {
		t.Errorf("scan with IP target: got %v, want IP validation error", err)
	}
}

func TestScanSubcommandExists(t *testing.T) {
	root := newRootCmd()
	if _, _, err := root.Find([]string{"scan"}); err != nil {
		t.Fatalf("scan subcommand not found: %v", err)
	}
}

// execCode runs the CLI tree through ExecuteArgsContext -- the same entry the
// binary and the in-process TUI use -- and returns the process exit code.
func execCode(t *testing.T, args ...string) int {
	t.Helper()
	return ExecuteArgsContext(context.Background(), args)
}

// TestRootRejectsUnknownCommand guards the core issue: a mistyped command must
// be reported as a usage error (exit 2), never re-scanned as a target domain.
func TestRootRejectsUnknownCommand(t *testing.T) {
	for _, args := range [][]string{
		{"hhelp"},
		{"scna"},
		{"scna", "example.com"},
		{"foo"},
	} {
		if code := execCode(t, args...); code != 2 {
			t.Errorf("execute %v: exit = %d, want 2 (usage error, not a scan)", args, code)
		}
	}
}

// TestRootSuggestsForMistypedCommand checks that a typo close to a real command
// carries cobra's "did you mean this?" hint, like every other QYVORA tool.
func TestRootSuggestsForMistypedCommand(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"scna"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected unknown-command error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("expected unknown-command error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "Did you mean this?") || !strings.Contains(err.Error(), "scan") {
		t.Fatalf("expected a suggestion for 'scan', got: %v", err)
	}
}

// TestRootRejectsDotlessTarget checks that a command-shaped word is an unknown
// command even when it reaches the target path explicitly via `scan`.
func TestRootRejectsDotlessTarget(t *testing.T) {
	if code := execCode(t, "example"); code != 2 {
		t.Errorf("bare dotless target: exit = %d, want 2", code)
	}
	root := newRootCmd()
	root.SetArgs([]string{"scan", "example"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "domain name") {
		t.Errorf("scan with dotless target: got %v, want domain-name error", err)
	}
}

// TestRootRejectsExtraArguments checks that a valid target followed by further
// positional arguments is a usage error rather than a silently dropped tail.
func TestRootRejectsExtraArguments(t *testing.T) {
	if code := execCode(t, "example.com", "extra"); code != 2 {
		t.Errorf("target plus extra argument: exit = %d, want 2", code)
	}
}

// TestSubcommandsRejectExtraArguments checks the version/tui/updates commands
// reject stray positionals with exit code 2, not the runtime-code 1 that a bare
// cobra.NoArgs would produce.
func TestSubcommandsRejectExtraArguments(t *testing.T) {
	for _, args := range [][]string{
		{"version", "extra"},
		{"tui", "extra"},
		{"updates", "extra"},
	} {
		if code := execCode(t, args...); code != 2 {
			t.Errorf("execute %v: exit = %d, want 2", args, code)
		}
	}
}
