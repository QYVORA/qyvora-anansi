// Package cmd implements the CLI command structure and orchestrates all scan phases.
// It uses the Cobra library to handle command-line parsing and flag management.
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/QYVORA/qyvora-anansi/internal/banner"
	"github.com/QYVORA/qyvora-anansi/internal/chain"
	"github.com/QYVORA/qyvora-anansi/internal/discovery"
	"github.com/QYVORA/qyvora-anansi/internal/events"
	"github.com/QYVORA/qyvora-anansi/internal/headers"
	"github.com/QYVORA/qyvora-anansi/internal/osint"
	"github.com/QYVORA/qyvora-anansi/internal/output"
	"github.com/QYVORA/qyvora-anansi/internal/paths"
	"github.com/QYVORA/qyvora-anansi/internal/probe"
	"github.com/QYVORA/qyvora-anansi/internal/takeover"
	"github.com/QYVORA/qyvora-anansi/internal/techstack"
	"github.com/QYVORA/qyvora-anansi/internal/tls"
	"github.com/QYVORA/qyvora-anansi/internal/version"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var updateFlag bool

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
	flagAuthorized bool
	flagExploitDry bool
	flagExploitSel string
)

// newVersionCmd builds the version command.  The installer and CI use it to
// verify a genuine binary is on the system. It honors the shared QYVORA
// output contract: `-o/--output json` emits a machine-readable object.
//
// It is a constructor rather than a package-level value because the TUI runs
// the command tree repeatedly in one process. A shared command is parsed and
// executed again on every keystroke-submitted line, and a command object that
// has already run carries its flag state forward into the next run.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the ANANSI CLI version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.GetInfo()
			if strings.EqualFold(flagOut, "json") {
				data, err := json.Marshal(info)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}
			if !strings.EqualFold(flagOut, "terminal") {
				return &usageError{fmt.Errorf("invalid output format %q for version (terminal, json)", flagOut)}
			}
			// Write to stdout explicitly. cobra's cmd.Print* helpers route to
			// OutOrStderr(), so `anansi version > file` used to produce an empty
			// file, and the installer's version probe -- which discards stderr --
			// saw no version at all and fell back to parsing the --help banner.
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "anansi %s\n", info.Version)
			fmt.Fprintf(w, "  framework:  %s\n", info.Framework)
			fmt.Fprintf(w, "  commit:     %s\n", info.Commit)
			fmt.Fprintf(w, "  built:      %s\n", info.Date)
			fmt.Fprintf(w, "  by:         %s\n", info.BuildUser)
			fmt.Fprintf(w, "  go:         %s %s/%s\n", info.GoVersion, info.OS, info.Arch)
			fmt.Fprintf(w, "  website:    %s\n", info.Website)
			fmt.Fprintf(w, "  support:    %s\n", info.Support)
			fmt.Fprintf(w, "  built in:   %s\n", info.BuiltIn)
			return nil
		},
	}
}

// newScanCmd builds the explicit scan command.  It exists so the REPL
// habit `anansi scan <target>` also works at the CLI; without it cobra would
// treat "scan" itself as the target domain.
func newScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan <target>",
		Short: "Run a scan against a target",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			return runScanTarget(args, false)
		},
	}
}

// newRootCmd builds the main Cobra command. It takes either no argument, which
// opens the interactive terminal application, or a single positional argument,
// which is the target domain to scan. The full ASCII art banner is shown in the
// help text.
//
// The tree is built per call rather than held in a package-level variable. The
// TUI runs the tree repeatedly in one process, and cobra binds every flag to a
// package-level variable at registration time: parse --deep on one line and the
// next line's scan inherits it, because nothing clears it. Rebuilding reapplies
// every default, so each command runs with exactly the flags it was given.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "anansi [target]",
		Short: "ANANSI — Attack Surface Intelligence Engine",
		Long: banner.Render() + `

  Attack Surface Intelligence Engine — ` + output.CompanyName + `
  ` + output.CompanyURL + `
  Built in ` + output.BuiltIn + `
`,
		// ArbitraryArgs keeps the root command accepting a bare positional
		// target even though it also has subcommands (e.g. `anansi version`).
		// Without this, cobra rejects `anansi target.com` as an unknown command.
		Args: cobra.ArbitraryArgs,
	}

	registerRootFlags(root)
	return attachSubcommands(root)
}

// Execute is called by main.go.  It runs the root Cobra command and
// exits with the canonical QYVORA code: 0 success, 1 runtime error,
// 2 usage error, 130 interrupt.
func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if code := ExecuteArgsContext(ctx, os.Args[1:]); code != 0 {
		os.Exit(code)
	}
}

// ExecuteArgsContext runs the command tree with an explicit argument vector
// under a caller-supplied context and returns the process exit code.
//
// The interactive TUI drives this form. It runs commands in-process on its own
// goroutine and must be able to cancel a single execution without tearing down
// the process, so the work follows a context the caller owns rather than
// process-wide signal handling. That is what makes Ctrl+C stop the operation
// itself instead of the window drawn around it.
func ExecuteArgsContext(ctx context.Context, args []string) int {
	root := newRootCmd()
	root.SetContext(ctx)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		var ue *usageError
		if errors.As(err, &ue) {
			return 2
		}
		if errors.Is(err, context.Canceled) {
			return 130
		}
		return 1
	}
	return 0
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
// registerRootFlags attaches anansi's flags to root.
func registerRootFlags(root *cobra.Command) {

	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &usageError{err}
	})
	pf := root.PersistentFlags()
	pf.BoolVar(&updateFlag, "update", false, "update the CLI to the latest official release")
	pf.BoolVar(&flagDeep, "deep", false, "Enable deep scan (larger wordlist, more path probing)")
	pf.StringVarP(&flagOut, "output", "o", "terminal", "Output format: terminal | json | markdown | html")
	// "out" is kept as a legacy alias; "--output"/-o is the canonical spelling.
	pf.StringVar(&flagOut, "out", "terminal", "Output format (legacy alias for --output")
	_ = pf.MarkHidden("out")
	root.PersistentFlags()
	pf.IntVar(&flagTimeout, "timeout", 5, "Per-request timeout in seconds")
	root.PersistentFlags()
	pf.StringSliceVar(&flagModules, "modules", append([]string(nil), defaultModules...), "Modules to run (comma-separated)")
	root.PersistentFlags()
	pf.StringVarP(&flagWordlist, "wordlist", "w", "", "Path to custom subdomain wordlist")
	root.PersistentFlags()
	pf.IntVarP(&flagThreads, "threads", "t", 100, "Number of concurrent threads")
	root.PersistentFlags()
	pf.BoolVarP(&flagVerbose, "verbose", "v", false, "Show all results including not-found/failed items")
	root.PersistentFlags()
	pf.BoolVarP(&flagRecursive, "recursive", "r", false, "Enable recursive subdomain brute-force on resolved subdomains")
	root.PersistentFlags()
	pf.BoolVarP(&flagMutate, "mutate", "m", false, "Enable subdomain mutation brute-force based on resolved prefixes")
	root.PersistentFlags()
	pf.IntVar(&flagDelay, "delay", 0, "Delay between requests in ms for rate limiting")
	root.PersistentFlags()
	pf.StringSliceVarP(&flagPorts, "ports", "p", []string{"80", "443"}, "Ports to probe (comma-separated)")
	root.PersistentFlags()
	pf.BoolVar(&flagStealth, "stealth", false, "Enable stealth mode: random UA, jitter, skip crt.sh, reduced concurrency")
	root.PersistentFlags()
	pf.BoolVar(&flagAuthorized, "authorized", false, "Confirm authorized testing before active PoC/exploitation runs (required for exploit module execution)")
	root.PersistentFlags()
	pf.BoolVar(&flagExploitDry, "exploit-dry-run", false, "Run the exploit phase in validation-only mode: no proof requests are executed")
	root.PersistentFlags()
	pf.StringVar(&flagOutputFile, "output-file", "", "Write output to file instead of stdout")
	root.PersistentFlags()
	pf.StringVar(&flagEvents, "events", "", "Emit JSONL event stream to stdout, stderr, or a file path (e.g. --events scan.jsonl)")
	root.Flags().Bool("version", false, "Print version information and exit")
}

// newRootCmdFlags attaches anansi's flags to a freshly built root. The
// defaults are declared once here and reapplied to every tree, which is what
// keeps one TUI command's flags out of the next.
func attachSubcommands(root *cobra.Command) *cobra.Command {
	// The default action is assigned here rather than in the literal above.
	// Go's initialisation dependency analysis follows references through
	// function bodies: the default action reaches runTUI, which needs the root,
	// so naming it inside the root's own initialiser is a cycle. A function
	// body is not part of initialisation.
	root.RunE = runScan
	// The TUI must be a real subcommand, not only the default action. anansi's
	// root takes a bare positional target, so without this `anansi tui` would
	// read "tui" as a hostname and start scanning it.
	root.AddCommand(commandTUI())
	root.AddCommand(newVersionCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newUpdatesCmd())
	root.AddCommand(newCompletionCmd())
	root.AddCommand(newExploitCmd())
	return root
}

// newCompletionCmd emits a shell completion script for bash/zsh/fish/powershell,
// matching the canonical completion verb shared by all QYVORA frameworks.
func newCompletionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion bash|zsh|fish|powershell",
		Short: "Generate a shell completion script",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Complete the tree this command actually belongs to. Reaching for
			// a package-level root here would be wrong twice over: it would be an
			// initialisation cycle, and it would complete a different tree from
			// the one the caller is running.
			root := cmd.Root()
			switch args[0] {
			case "bash":
				return root.GenBashCompletionV2(cmd.OutOrStdout(), true)
			case "zsh":
				return root.GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return root.GenFishCompletion(cmd.OutOrStdout(), true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
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

// dedupeFindings removes duplicate findings by title + affected asset and
// assigns each surviving finding a stable per-scan identifier (F-<n>). The
// paths and tech modules intentionally probe overlapping targets (e.g. /.env
// and /.git/HEAD appear in both generic lists), so a final pass keeps the
// report clean. The function is idempotent: calling it again on its own
// output re-assigns identical IDs because ordering and content are unchanged.
func dedupeFindings(findings []output.Finding) []output.Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]output.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Title + "\x00" + f.AffectedAsset
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		f.ID = fmt.Sprintf("F-%04d", len(out)+1)
		out = append(out, f)
	}
	return out
}

// runScan is the top-level scan orchestrator.  With no arguments it drops the
// user into the interactive Metasploit-style console; otherwise it validates
// the target and runs the enabled modules.
func runScan(cmd *cobra.Command, args []string) error {
	if showVersion, _ := cmd.Flags().GetBool("version"); showVersion {
		fmt.Fprintln(cmd.OutOrStdout(), version.Version)
		return nil
	}
	if len(args) == 0 {
		// No target means no scan to perform, so this is the interactive case.
		// The root is passed in: the default action calls runTUI, so naming the
		// package-level root from inside it would be an initialisation cycle.
		return runTUI(cmd.Root(), cmd.Context())
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
	if flagEvents == "stdout" {
		// stdout carries exactly one machine stream. With the event JSONL
		// stream owning stdout, a machine report format cannot share it
		// (use --events stderr or --events <file>), and human/report output
		// routes to stderr so stdout stays pure JSONL. Renderers print via
		// fmt/os.Stdout directly, so both the os.Stdout handle and the
		// fatih/color global Output are redirected.
		if !strings.EqualFold(flagOut, "terminal") {
			return &usageError{fmt.Errorf("cannot combine --events stdout with report format -o %s; use --events stderr or --events <file>", flagOut)}
		}
		restoreStdout := os.Stdout
		os.Stdout = os.Stderr
		restoreColor := color.Output
		color.Output = os.Stderr
		defer func() {
			os.Stdout = restoreStdout
			color.Output = restoreColor
		}()
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
		"version": version.Version,
		"modules": flagModules,
		"stealth": flagStealth,
	})
	phaseEmit := func(module, _ string, name string) func() {
		emit(events.LevelInfo, events.PhaseStarted, map[string]any{"phase": module, "name": name})
		return func() {
			emit(events.LevelInfo, events.PhaseCompleted, map[string]any{"phase": module, "name": name})
		}
	}
	findingsEmit := func(findings []output.Finding) {
		for _, f := range findings {
			emit(events.LevelInfo, events.FindingDiscovered, map[string]any{
				"id":       f.ID,
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

	// Phase progress for the activity view: one step per enabled module, so
	// the shared terminal's activity region and progress bar move with the
	// scan rather than sitting still until a phase ends.
	totalPhases := 0
	for _, m := range flagModules {
		if hasModule(m) {
			totalPhases++
		}
	}
	if totalPhases < 1 {
		totalPhases = 1
	}
	phaseRun := 0
	progressEmit := func(message string) {
		phaseRun++
		emit(events.LevelInfo, events.ProgressUpdated, map[string]any{
			"message": message,
			"current": phaseRun,
			"total":   totalPhases,
		})
	}

	// -- PHASE 1: DISCOVERY ------------------------------------------------
	if hasModule("discovery") {
		progressEmit("DISCOVERY")
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
		progressEmit("PROBE")
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
		progressEmit("TLS")
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
		progressEmit("HEADERS")
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
		progressEmit("PATHS")
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
		progressEmit("TECH-STACK")
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
		progressEmit("TAKEOVER")
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
		progressEmit("OSINT")
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
		progressEmit("CHAIN")
		done := phaseEmit("chain", "09", "CHAIN")
		out.PhaseHeader("09", "CHAIN", "multi-step exploit path assembly from findings")
		chains := chain.Run(report.Findings)
		report.Chains = chains
		out.ChainTable(chains)
		done()
	}

	// -- PHASE 10: EXPLOIT / PoC ------------------------------------------
	// The framework-native exploitation layer. Each finding with a matching
	// PoC module is taken through validation -> exploitable -> (authorized)
	// proof -> evidence. Without --authorized no active request is made and
	// results carry the authorization_required state; with --exploit-dry-run
	// validation runs but proof execution is skipped.
	if hasModule("exploit") {
		progressEmit("EXPLOIT")
		done := phaseEmit("exploit", "10", "EXPLOIT")
		out.PhaseHeader("10", "EXPLOIT", "controlled PoC validation and exploitation of findings")
		report.ExploitResults = runExploitPhase(out, report, emit)
		out.ExploitResultsBlock(report.ExploitResults)
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

	// The bar completes wherever the scan stopped, even when phases were
	// skipped because there was no data for them: a finished scan reports a
	// finished bar.
	phaseRun = totalPhases
	emit(events.LevelInfo, events.ProgressUpdated, map[string]any{
		"message": "Done",
		"current": totalPhases,
		"total":   totalPhases,
	})

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
		"exploit_runs":   len(report.ExploitResults),
	})

	return nil
}
