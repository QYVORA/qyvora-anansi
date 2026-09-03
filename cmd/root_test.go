package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-anansi/internal/output"
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
	old := Version
	Version = "test-1.2.3"
	defer func() { Version = old }()

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"--version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute --version: %v", err)
	}
	if got := buf.String(); got != "test-1.2.3\n" {
		t.Errorf("--version printed %q, want %q", got, "test-1.2.3\n")
	}
}

func TestVersionSubcommandPrintsVersion(t *testing.T) {
	old := Version
	Version = "v9.9.9-rc1"
	defer func() { Version = old }()

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute version subcommand: %v", err)
	}
	if got := buf.String(); got != "v9.9.9-rc1\n" {
		t.Errorf("version subcommand printed %q, want %q", got, "v9.9.9-rc1\n")
	}
}

// TestVersionSubcommandJSONOutput verifies the shared QYVORA output contract:
// `-o json` on the version verb emits a machine-readable object, and an
// unsupported format is rejected as a usage error.
func TestVersionSubcommandJSONOutput(t *testing.T) {
	old := Version
	Version = "v9.9.9-rc1"
	defer func() { Version = old }()

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"version", "-o", "json"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute version -o json: %v", err)
	}
	var parsed map[string]string
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("version -o json emitted invalid JSON %q: %v", buf.String(), err)
	}
	if parsed["framework"] != "anansi" || parsed["version"] != "v9.9.9-rc1" {
		t.Errorf("version -o json = %v, want framework=anansi version=v9.9.9-rc1", parsed)
	}

	rootCmd.SetOut(&buf)
	buf.Reset()
	rootCmd.SetArgs([]string{"version", "-o", "yaml"})
	err := rootCmd.Execute()
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
	if err := rootCmd.Flags().Set("version", "false"); err != nil {
		t.Fatalf("resetting version flag: %v", err)
	}
	rootCmd.SetArgs([]string{"192.168.1.1"})
	err := rootCmd.Execute()
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
	rootCmd.SetArgs([]string{"scan"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "1 arg") {
		t.Errorf("scan without target: got %v, want arg-count error", err)
	}
}

func TestScanSubcommandRejectsIPTarget(t *testing.T) {
	rootCmd.SetArgs([]string{"scan", "192.168.1.1"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "not an IP") {
		t.Errorf("scan with IP target: got %v, want IP validation error", err)
	}
}

func TestScanSubcommandExists(t *testing.T) {
	if _, _, err := rootCmd.Find([]string{"scan"}); err != nil {
		t.Fatalf("scan subcommand not found: %v", err)
	}
}
