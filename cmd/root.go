// Package cmd implements the CLI command structure and orchestrates all scan phases.
// It uses the Cobra library to handle command-line parsing and flag management.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/QYVORA/qyvora-anansi-cli/internal/chain"
	"github.com/QYVORA/qyvora-anansi-cli/internal/discovery"
	"github.com/QYVORA/qyvora-anansi-cli/internal/events"
	"github.com/QYVORA/qyvora-anansi-cli/internal/headers"
	"github.com/QYVORA/qyvora-anansi-cli/internal/osint"
	"github.com/QYVORA/qyvora-anansi-cli/internal/output"
	"github.com/QYVORA/qyvora-anansi-cli/internal/paths"
	"github.com/QYVORA/qyvora-anansi-cli/internal/probe"
	"github.com/QYVORA/qyvora-anansi-cli/internal/takeover"
	"github.com/QYVORA/qyvora-anansi-cli/internal/techstack"
	"github.com/QYVORA/qyvora-anansi-cli/internal/tls"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	flagDeep       bool
	flagOut        string
	flagOutputFile string
	flagTimeout    int
	flagModules    []string
	flagWordlist   string
	flagThreads    int
	flagVerbose    bool
	flagRecursive  bool
	flagMutate     bool
	flagDelay      int
	flagPorts      []string
	flagStealth    bool
)

// Version is stamped at build time via:
//
//	-ldflags "-X github.com/QYVORA/qyvora-anansi-cli/cmd.Version=<version>"
//
// It defaults to "dev" for local builds.
var Version = "dev"

// versionCmd prints the build version.  The installer and CI use it to
// verify a genuine binary is on the system.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the ANANSI CLI version",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		cmd.Println(Version)
	},
}

// scanCmd runs a scan against an explicit target.  It exists so the REPL
// habit `anansi scan <target>` also works at the CLI; without it cobra would
// treat "scan" itself as the target domain.
var scanCmd = &cobra.Command{
	Use:   "scan <target>",
	Short: "Run a scan against a target",
	Args:  usageArgs(cobra.ExactArgs(1)),
	RunE: func(_ *cobra.Command, args []string) error {
		return runScanTarget(args, false)
	},
}

// rootCmd is the main Cobra command.  It requires exactly one argument:
// the target domain to scan.  The full ASCII art banner is shown in the
// help text.
var rootCmd = &cobra.Command{
	Use:   "anansi [target]",
	Short: "ANANSI — Attack Surface Intelligence Engine",
	Long: color.New(color.FgCyan, color.Bold).Sprint(output.AnansiASCIIArt) + `

  Attack Surface Intelligence Engine — ` + output.CompanyName + `
  ` + output.CompanyURL + `
  Built in ` + output.BuiltIn + `
`,
	// ArbitraryArgs keeps the root command accepting a bare positional
	// target even though it also has subcommands (e.g. `anansi version`).
	// Without this, cobra rejects `anansi target.com` as an unknown command.
	Args: cobra.ArbitraryArgs,
	RunE: runScan,
}

// Execute is called by main.go.  It runs the root Cobra command and
// exits with the canonical QYVORA code: 0 success, 1 runtime error,
// 2 usage error, 130 interrupt.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		code := 1
		var ue *usageError
		if errors.As(err, &ue) {
			code = 2
		}
		os.Exit(code)
	}
}

// usageError marks a command-line usage problem (bad flag or argument) so the
// process can exit 2 instead of 1 per the shared QYVORA exit-code contract.
type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

// usageArgs wraps a cobra Args validator so arg-count violations exit 2.
func usageArgs(validate cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := validate(cmd, args); err != nil {
			return &usageError{err}
		}
		return nil
	}
}

// init registers all CLI flags with their default values and help text.
// They are registered as persistent flags so the `scan` and `version`
// subcommands inherit the same option set as the bare `anansi <target>` form.
func init() {
	rootCmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &usageError{err}
	})
	rootCmd.PersistentFlags().BoolVar(&flagDeep, "deep", false, "Enable deep scan (larger wordlist, more path probing)")
	rootCmd.PersistentFlags().StringVarP(&flagOut, "output", "o", "terminal", "Output format: terminal | json | markdown | html")
	// "out" is kept as a legacy alias; "--output"/-o is the canonical spelling.
	rootCmd.PersistentFlags().StringVar(&flagOut, "out", "terminal", "Output format (legacy alias for --output)")
	_ = rootCmd.PersistentFlags().MarkHidden("out")
	rootCmd.PersistentFlags().IntVar(&flagTimeout, "timeout", 5, "Per-request timeout in seconds")
	rootCmd.PersistentFlags().StringSliceVar(&flagModules, "modules", append([]string(nil), defaultModules...), "Modules to run (comma-separated)")
	rootCmd.PersistentFlags().StringVarP(&flagWordlist, "wordlist", "w", "", "Path to custom subdomain wordlist")
	rootCmd.PersistentFlags().IntVarP(&flagThreads, "threads", "t", 100, "Number of concurrent threads")
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "Show all results including not-found/failed items")
	rootCmd.PersistentFlags().BoolVarP(&flagRecursive, "recursive", "r", false, "Enable recursive subdomain brute-force on resolved subdomains")
	rootCmd.PersistentFlags().BoolVarP(&flagMutate, "mutate", "m", false, "Enable subdomain mutation brute-force based on resolved prefixes")
	rootCmd.PersistentFlags().IntVar(&flagDelay, "delay", 0, "Delay between requests in ms for rate limiting")
	rootCmd.PersistentFlags().StringSliceVarP(&flagPorts, "ports", "p", []string{"80", "443"}, "Ports to probe (comma-separated)")
	rootCmd.PersistentFlags().BoolVar(&flagStealth, "stealth", false, "Enable stealth mode: random UA, jitter, skip crt.sh, reduced concurrency")
	rootCmd.PersistentFlags().StringVar(&flagOutputFile, "output-file", "", "Write output to file instead of stdout")
	rootCmd.PersistentFlags().StringVar(&flagEvents, "events", "", "Emit JSONL event stream to stdout, stderr, or a file path (e.g. --events scan.jsonl)")
	rootCmd.Flags().Bool("version", false, "Print version information and exit")
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(newCompletionCmd())
}

// newCompletionCmd emits a shell completion script for bash/zsh/fish/powershell,
// matching the canonical completion verb shared by all QYVORA frameworks.
func newCompletionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion bash|zsh|fish|powershell",
		Short: "Generate a shell completion script",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return rootCmd.GenBashCompletionV2(cmd.OutOrStdout(), true)
			case "zsh":
				return rootCmd.GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return rootCmd.GenFishCompletion(cmd.OutOrStdout(), true)
			case "powershell":
				return rootCmd.GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
			default:
				return &usageError{fmt.Errorf("unknown shell %q (bash, zsh, fish, powershell)", args[0])}
			}
		},
	}
}

// hasModule reports whether the given module name is present in the
// --modules flag (case-insensitive).
func hasModule(name string) bool {
	for _, m := range flagModules {
		if strings.EqualFold(strings.TrimSpace(m), name) {
			return true
		}
	}
	return false
}

// dedupeFindings removes duplicate findings by title + affected asset.  The
// paths and tech modules intentionally probe overlapping targets (e.g. /.env
// and /.git/HEAD appear in both generic lists), so a final pass keeps the
// report clean.
func dedupeFindings(findings []output.Finding) []output.Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]output.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Title + "\x00" + f.AffectedAsset
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

// runScan is the top-level scan orchestrator.  With no arguments it drops the
// user into the interactive Metasploit-style console; otherwise it validates
// the target and runs the enabled modules.
func runScan(cmd *cobra.Command, args []string) error {
	if showVersion, _ := cmd.Flags().GetBool("version"); showVersion {
		cmd.Println(Version)
		return nil
	}
	if len(args) == 0 {
		return runConsole()
	}
	return runScanTarget(args, false)
}

// runScanTarget validates the target, then runs each enabled module in
// sequence, passing results between phases.  When console is true (invoked
// from the interactive console) an interrupt prints partial results and
// returns to the prompt instead of exiting the process.
func runScanTarget(args []string, console bool) error {
	target := strings.ToLower(strings.TrimSpace(args[0]))
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.Split(target, "/")[0]

	if target == "" {
		return fmt.Errorf("invalid target: empty after parsing")
	}

	// Basic DNS-label validation: reject IPs, empty labels, and overly long domains.
	if net.ParseIP(target) != nil {
		return fmt.Errorf("invalid target: use a domain name, not an IP address (%s)", target)
	}
	labels := strings.Split(target, ".")
	for _, lbl := range labels {
		if lbl == "" {
			return fmt.Errorf("invalid target: malformed domain '%s' (empty label)", target)
		}
	}
	if len(target) > 253 {
		return fmt.Errorf("invalid target: domain exceeds 253 characters (%d)", len(target))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startTime := time.Now()
	out := output.New(flagOut, flagVerbose)
	if flagStealth {
		out = out.WithStealth()
	}

	// Bind the optional JSONL event stream to this run before any phase
	// executes so the full lifecycle (scan.started .. scan.completed) is
	// captured.
	emitter, closeStream, err := newEventsEmitter()
	if err != nil {
		return err
	}
	if closeStream != nil {
		defer closeStream()
	}
	emit := func(level, name string, data map[string]any) {
		if emitter != nil {
			emitter.Emit("anansi", level, name, data)
		}
	}

	report := &output.Report{
		Target:    target,
		StartedAt: startTime,
	}

	emit(events.LevelInfo, events.ScanStarted, map[string]any{
		"target":  target,
		"version": Version,
		"modules": flagModules,
		"stealth": flagStealth,
	})
	phaseEmit := func(module, num, name string) func() {
		emit(events.LevelInfo, events.PhaseStarted, map[string]any{"phase": module, "name": name})
		return func() {
			emit(events.LevelInfo, events.PhaseCompleted, map[string]any{"phase": module, "name": name})
		}
	}
	findingsEmit := func(findings []output.Finding) {
		for _, f := range findings {
			emit(events.LevelInfo, events.FindingDiscovered, map[string]any{
				"title":    f.Title,
				"severity": f.Severity,
				"asset":    f.AffectedAsset,
			})
		}
	}

	// scanDone is closed once the scan finishes cleanly.  The interrupt
	// goroutine races with the main scan, so without it a signal arriving
	// after completion (but before process exit) would print a spurious
	// "interrupted" block and force exit code 130.
	scanDone := make(chan struct{})
	defer close(scanDone)

	go func() {
		select {
		case <-ctx.Done():
			report.Duration = time.Since(startTime)
			emit(events.LevelWarning, events.ScanInterrupted, map[string]any{
				"duration_ms":    report.Duration.Milliseconds(),
				"findings_count": len(report.Findings),
			})
			out.Banner(target)
			out.Info("Scan interrupted by user. Printing partial results...")
			out.Summary(report)
			if !console {
				os.Exit(130)
			}
		case <-scanDone:
		}
	}()

	out.Banner(target)

	// -- PHASE 1: DISCOVERY ------------------------------------------------
	if hasModule("discovery") {
		done := phaseEmit("discovery", "01", "DISCOVERY")
		out.PhaseHeader("01", "DISCOVERY", "subdomain enumeration + DNS resolution")
		subdomains, err := discovery.Run(out, target, flagDeep, flagTimeout, flagWordlist, flagThreads, flagRecursive, flagMutate, flagDelay, flagStealth)
		if err != nil {
			emit(events.LevelError, events.Error, map[string]any{"phase": "discovery", "message": err.Error()})
			out.PhaseError("DISCOVERY", err)
		} else {
			report.Subdomains = subdomains
			out.SubdomainTable(subdomains)
		}
		done()
	}

	// -- PHASE 2: PROBE ----------------------------------------------------
	if hasModule("probe") && len(report.Subdomains) > 0 {
		done := phaseEmit("probe", "02", "PROBE")
		out.PhaseHeader("02", "PROBE", "HTTP/HTTPS surface mapping")
		hosts := discovery.LiveHosts(report.Subdomains)
		probeResults, err := probe.Run(out, hosts, flagTimeout, flagThreads, flagPorts, flagDelay, flagStealth)
		if err != nil {
			emit(events.LevelError, events.Error, map[string]any{"phase": "probe", "message": err.Error()})
			out.PhaseError("PROBE", err)
		} else {
			report.ProbeResults = probeResults
			out.ProbeTable(probeResults)
		}
		done()
	}

	// -- PHASE 3: TLS ------------------------------------------------------
	if hasModule("tls") && len(report.ProbeResults) > 0 {
		done := phaseEmit("tls", "03", "TLS")
		out.PhaseHeader("03", "TLS", "certificate analysis + SAN discovery")
		liveHosts := probe.LiveOnly(report.ProbeResults)
		tlsResults, newSubdomains := tls.Run(liveHosts, target, flagTimeout, flagThreads, flagDelay, flagStealth)
		report.TLSResults = tlsResults
		if len(newSubdomains) > 0 {
			out.Info(fmt.Sprintf("SAN discovery found %d additional subdomains", len(newSubdomains)))
			report.Subdomains = append(report.Subdomains, newSubdomains...)
		}
		out.TLSTable(tlsResults)
		for _, r := range tlsResults {
			findingsEmit(r.Findings)
			report.Findings = append(report.Findings, r.Findings...)
		}
		done()
	}

	// -- PHASE 4: HEADERS --------------------------------------------------
	if hasModule("headers") && len(report.ProbeResults) > 0 {
		done := phaseEmit("headers", "04", "HEADERS")
		out.PhaseHeader("04", "HEADERS", "security header audit")
		liveHosts := probe.LiveOnly(report.ProbeResults)
		headerResults := headers.Run(report.ProbeResults, liveHosts, flagTimeout, flagThreads, flagDelay, flagStealth)
		report.HeaderResults = headerResults
		out.HeadersTable(headerResults)
		for _, r := range headerResults {
			findingsEmit(r.Findings)
			report.Findings = append(report.Findings, r.Findings...)
		}
		done()
	}

	// -- PHASE 5: PATHS ----------------------------------------------------
	if hasModule("paths") && len(report.ProbeResults) > 0 {
		done := phaseEmit("paths", "05", "PATHS")
		out.PhaseHeader("05", "PATHS", "exposed endpoint + file detection")
		liveHosts := probe.LiveOnly(report.ProbeResults)
		pathFindings := paths.Run(out, liveHosts, flagDeep, flagTimeout, flagThreads, flagDelay, flagStealth)
		findingsEmit(pathFindings)
		report.Findings = append(report.Findings, pathFindings...)
		out.FindingsBlock("PATHS", pathFindings)
		done()
	}

	// -- PHASE 6: TECH-STACK DEEP AUDIT ------------------------------
	if hasModule("tech") && len(report.ProbeResults) > 0 {
		done := phaseEmit("tech", "06", "TECH-STACK")
		out.PhaseHeader("06", "TECH-STACK", "CMS fingerprinting + version-specific vulnerability audit")
		liveHosts := probe.LiveOnly(report.ProbeResults)
		techResults := techstack.Run(out, liveHosts, flagTimeout, flagThreads, flagDelay, flagStealth)
		report.TechResults = techResults
		for _, tr := range techResults {
			findingsEmit(tr.Findings)
			report.Findings = append(report.Findings, tr.Findings...)
		}
		out.TechTable(techResults)
		done()
	}

	// -- PHASE 7: TAKEOVER -------------------------------------------------
	if hasModule("takeover") && len(report.Subdomains) > 0 {
		done := phaseEmit("takeover", "07", "TAKEOVER")
		out.PhaseHeader("07", "TAKEOVER", "dangling CNAME subdomain takeover detection")
		takeoverFindings := takeover.Run(out, report.Subdomains, flagTimeout, flagThreads, flagDelay, flagStealth)
		findingsEmit(takeoverFindings)
		report.Findings = append(report.Findings, takeoverFindings...)
		out.FindingsBlock("TAKEOVER", takeoverFindings)
		done()
	}

	// -- PHASE 8: OSINT ----------------------------------------------------
	if hasModule("osint") {
		done := phaseEmit("osint", "08", "OSINT")
		out.PhaseHeader("08", "OSINT", "organisation recon — emails, phones, WHOIS, employees")
		osintResults := osint.Run(out, report.ProbeResults, target, flagTimeout, flagThreads, flagDelay, flagStealth)
		report.OSINTResults = osintResults
		out.OSINTTable(osintResults)
		done()
	}

	// -- PHASE 9: EXPLOIT CHAIN ANALYSIS ----------------------------------
	report.Findings = dedupeFindings(report.Findings)
	if hasModule("chain") {
		done := phaseEmit("chain", "09", "CHAIN")
		out.PhaseHeader("09", "CHAIN", "multi-step exploit path assembly from findings")
		chains := chain.Run(report.Findings)
		report.Chains = chains
		out.ChainTable(chains)
		done()
	}

	// -- SUMMARY -----------------------------------------------------------
	report.Duration = time.Since(startTime)
	report.Findings = dedupeFindings(report.Findings)

	if flagOutputFile != "" {
		f, err := os.Create(flagOutputFile)
		if err != nil {
			emit(events.LevelError, events.Error, map[string]any{"message": err.Error()})
			return fmt.Errorf("creating output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		oldStdout := os.Stdout
		os.Stdout = f
		out.Summary(report)
		os.Stdout = oldStdout
		out.Info(fmt.Sprintf("Report written to %s", flagOutputFile))
	} else {
		out.Summary(report)
	}

	emit(events.LevelInfo, events.ReportGenerated, map[string]any{
		"output": flagOutputFile,
		"format": flagOut,
	})
	emit(events.LevelInfo, events.ScanCompleted, map[string]any{
		"duration_ms":    report.Duration.Milliseconds(),
		"findings_count": len(report.Findings),
		"subdomains":     len(report.Subdomains),
		"hosts":          len(report.ProbeResults),
		"chains":         len(report.Chains),
	})

	return nil
}
