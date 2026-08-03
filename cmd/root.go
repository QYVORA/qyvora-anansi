// Package cmd implements the CLI command structure and orchestrates all scan phases.
// It uses the Cobra library to handle command-line parsing and flag management.
package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-anansi-cli/internal/chain"
	"github.com/QYVORA/qyvora-anansi-cli/internal/discovery"
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
// exits with a non-zero status code on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// init registers all CLI flags with their default values and help text.
func init() {
	rootCmd.Flags().BoolVar(&flagDeep, "deep", false, "Enable deep scan (larger wordlist, more path probing)")
	rootCmd.Flags().StringVar(&flagOut, "out", "terminal", "Output format: terminal | json | markdown | html")
	rootCmd.Flags().IntVar(&flagTimeout, "timeout", 5, "Per-request timeout in seconds")
	rootCmd.Flags().StringSliceVar(&flagModules, "modules", append([]string(nil), defaultModules...), "Modules to run (comma-separated)")
	rootCmd.Flags().StringVarP(&flagWordlist, "wordlist", "w", "", "Path to custom subdomain wordlist")
	rootCmd.Flags().IntVarP(&flagThreads, "threads", "t", 100, "Number of concurrent threads")
	rootCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Show all results including not-found/failed items")
	rootCmd.Flags().BoolVarP(&flagRecursive, "recursive", "r", false, "Enable recursive subdomain brute-force on resolved subdomains")
	rootCmd.Flags().BoolVarP(&flagMutate, "mutate", "m", false, "Enable subdomain mutation brute-force based on resolved prefixes")
	rootCmd.Flags().IntVar(&flagDelay, "delay", 0, "Delay between requests in ms for rate limiting")
	rootCmd.Flags().StringSliceVarP(&flagPorts, "ports", "p", []string{"80", "443"}, "Ports to probe (comma-separated)")
	rootCmd.Flags().BoolVar(&flagStealth, "stealth", false, "Enable stealth mode: random UA, jitter, skip crt.sh, reduced concurrency")
	rootCmd.Flags().StringVar(&flagOutputFile, "output-file", "", "Write output to file instead of stdout")
	rootCmd.Flags().Bool("version", false, "Print version information and exit")
	rootCmd.AddCommand(versionCmd)
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()

	startTime := time.Now()
	out := output.New(flagOut, flagVerbose)
	if flagStealth {
		out = out.WithStealth()
	}

	report := &output.Report{
		Target:    target,
		StartedAt: startTime,
	}

	go func() {
		<-ctx.Done()
		report.Duration = time.Since(startTime)
		out.Banner(target)
		out.Info("Scan interrupted by user. Printing partial results...")
		out.Summary(report)
		if !console {
			os.Exit(130)
		}
	}()

	out.Banner(target)

	// -- PHASE 1: DISCOVERY ------------------------------------------------
	if hasModule("discovery") {
		out.PhaseHeader("01", "DISCOVERY", "subdomain enumeration + DNS resolution")
		subdomains, err := discovery.Run(out, target, flagDeep, flagTimeout, flagWordlist, flagThreads, flagRecursive, flagMutate, flagDelay, flagStealth)
		if err != nil {
			out.PhaseError("DISCOVERY", err)
		} else {
			report.Subdomains = subdomains
			out.SubdomainTable(subdomains)
		}
	}

	// -- PHASE 2: PROBE ----------------------------------------------------
	if hasModule("probe") && len(report.Subdomains) > 0 {
		out.PhaseHeader("02", "PROBE", "HTTP/HTTPS surface mapping")
		hosts := discovery.LiveHosts(report.Subdomains)
		probeResults, err := probe.Run(out, hosts, flagTimeout, flagThreads, flagPorts, flagDelay, flagStealth)
		if err != nil {
			out.PhaseError("PROBE", err)
		} else {
			report.ProbeResults = probeResults
			out.ProbeTable(probeResults)
		}
	}

	// -- PHASE 3: TLS ------------------------------------------------------
	if hasModule("tls") && len(report.ProbeResults) > 0 {
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
			report.Findings = append(report.Findings, r.Findings...)
		}
	}

	// -- PHASE 4: HEADERS --------------------------------------------------
	if hasModule("headers") && len(report.ProbeResults) > 0 {
		out.PhaseHeader("04", "HEADERS", "security header audit")
		liveHosts := probe.LiveOnly(report.ProbeResults)
		headerResults := headers.Run(report.ProbeResults, liveHosts, flagTimeout, flagThreads, flagDelay, flagStealth)
		report.HeaderResults = headerResults
		out.HeadersTable(headerResults)
		for _, r := range headerResults {
			report.Findings = append(report.Findings, r.Findings...)
		}
	}

	// -- PHASE 5: PATHS ----------------------------------------------------
	if hasModule("paths") && len(report.ProbeResults) > 0 {
		out.PhaseHeader("05", "PATHS", "exposed endpoint + file detection")
		liveHosts := probe.LiveOnly(report.ProbeResults)
		pathFindings := paths.Run(out, liveHosts, flagDeep, flagTimeout, flagThreads, flagDelay, flagStealth)
		report.Findings = append(report.Findings, pathFindings...)
		out.FindingsBlock("PATHS", pathFindings)
	}

	// -- PHASE 6: TECH-STACK DEEP AUDIT ------------------------------
	if hasModule("tech") && len(report.ProbeResults) > 0 {
		out.PhaseHeader("06", "TECH-STACK", "CMS fingerprinting + version-specific vulnerability audit")
		liveHosts := probe.LiveOnly(report.ProbeResults)
		techResults := techstack.Run(out, liveHosts, flagTimeout, flagThreads, flagDelay, flagStealth)
		report.TechResults = techResults
		for _, tr := range techResults {
			report.Findings = append(report.Findings, tr.Findings...)
		}
		out.TechTable(techResults)
	}

	// -- PHASE 7: TAKEOVER -------------------------------------------------
	if hasModule("takeover") && len(report.Subdomains) > 0 {
		out.PhaseHeader("07", "TAKEOVER", "dangling CNAME subdomain takeover detection")
		takeoverFindings := takeover.Run(out, report.Subdomains, flagTimeout, flagThreads, flagDelay, flagStealth)
		report.Findings = append(report.Findings, takeoverFindings...)
		out.FindingsBlock("TAKEOVER", takeoverFindings)
	}

	// -- PHASE 8: OSINT ----------------------------------------------------
	if hasModule("osint") {
		out.PhaseHeader("08", "OSINT", "organisation recon — emails, phones, WHOIS, employees")
		osintResults := osint.Run(out, report.ProbeResults, target, flagTimeout, flagThreads, flagDelay, flagStealth)
		report.OSINTResults = osintResults
		out.OSINTTable(osintResults)
	}

	// -- PHASE 9: EXPLOIT CHAIN ANALYSIS ----------------------------------
	report.Findings = dedupeFindings(report.Findings)
	if hasModule("chain") {
		out.PhaseHeader("09", "CHAIN", "multi-step exploit path assembly from findings")
		chains := chain.Run(report.Findings)
		report.Chains = chains
		out.ChainTable(chains)
	}

	// -- SUMMARY -----------------------------------------------------------
	report.Duration = time.Since(startTime)
	report.Findings = dedupeFindings(report.Findings)

	if flagOutputFile != "" {
		f, err := os.Create(flagOutputFile)
		if err != nil {
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

	return nil
}
