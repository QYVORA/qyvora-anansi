// Package output implements report rendering for terminal, JSON, Markdown,
// and HTML output formats.  The Renderer struct is the primary consumer-facing
// API used by every scan phase to display progress and results.
package output

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
)

var (
	accent    = color.New(color.FgHiGreen, color.Bold)
	accentDim = color.New(color.FgHiGreen)
	white     = color.New(color.FgWhite, color.Bold)
	dim       = color.New(color.FgHiBlack)
	red       = color.New(color.FgRed, color.Bold)
	redDim    = color.New(color.FgRed)
	orange    = color.New(color.FgYellow, color.Bold)
	green     = color.New(color.FgGreen, color.Bold)
	greenDim  = color.New(color.FgGreen)
)

// ANSI palette for the ANANSI banner. ansiBody is the logo cyan (#10B0E8);
// ansiFace renders the logo's near-black face detail white so it stays
// visible on a dark terminal. True-color codes are emitted directly because
// the bundled fatih/color version predates color.RGB.
const (
	ansiBody = "\x1b[38;2;16;176;232m"
	ansiFace = "\x1b[38;2;255;255;255m"
)

// renderBannerLine paints one line of the ANANSI art in the logo palette:
// ';' is the cyan spider body, the remaining glyphs are the face detail
// rendered white. Spaces pass through untouched.
func renderBannerLine(line string) string {
	var b strings.Builder
	for _, r := range line {
		switch {
		case r == ' ':
			b.WriteRune(r)
		case r == ';':
			b.WriteString(ansiBody + string(r) + "\x1b[0m")
		default:
			b.WriteString(ansiFace + string(r) + "\x1b[0m")
		}
	}
	return b.String()
}

// Renderer manages output formatting and verbosity.  It is created once per
// scan and passed to every module so they can display progress inline.
type Renderer struct {
	format  string
	verbose bool
	stealth bool
	tty     bool
}

// New creates a Renderer for the given format and verbosity setting.
func New(format string, verbose bool) *Renderer {
	return &Renderer{
		format:  format,
		verbose: verbose,
		tty:     stdoutIsTerminal(),
	}
}

// stdoutIsTerminal reports whether standard output is attached to a real
// terminal (character device) rather than a pipe or file.
func stdoutIsTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// WithStealth returns a copy of the Renderer with stealth mode enabled.
func (r *Renderer) WithStealth() *Renderer {
	r.stealth = true
	return r
}

func (r *Renderer) isQuiet() bool {
	return r.format == "json" || r.format == "html" || r.format == "markdown"
}

// Verbose prints a message only when the --verbose flag is set and the
// output format is terminal.
func (r *Renderer) Verbose(msg string) {
	if r.isQuiet() {
		return
	}
	if r.verbose {
		dim.Printf("  [v] %s\n", msg)
	}
}

// Banner displays the ANANSI ASCII art, target, and scan start time.
// In stealth mode the banner is skipped entirely.
func (r *Renderer) Banner(target string) {
	if r.isQuiet() || r.stealth {
		return
	}
	fmt.Println()
	for _, line := range strings.Split(AnansiASCIIArt, "\n") {
		fmt.Println(renderBannerLine(line))
	}
	fmt.Println()
	fmt.Println()
	white.Println("  Attack Surface Intelligence Engine")
	accent.Printf("  %s — %s\n", CompanyName, CompanyURL)
	dim.Printf("  Built in %s\n\n", BuiltIn)
	dim.Printf("  TARGET: ")
	white.Println(target)
	dim.Printf("  TIME:   ")
	fmt.Println(time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Println()
}

func (r *Renderer) PhaseHeader(num, name, _ string) {
	if r.isQuiet() {
		return
	}
	fmt.Println()
	accent.Printf("  [+] PHASE %s: %s\n", num, name)
}

func (r *Renderer) PhaseError(phase string, err error) {
	if r.isQuiet() {
		return
	}
	redDim.Printf("  [!] %s error: %s\n", phase, err.Error())
}

func (r *Renderer) Info(msg string) {
	if r.isQuiet() {
		return
	}
	accentDim.Printf("  [*] %s\n", msg)
}

func (r *Renderer) Progress(current, total int, label string) {
	// Carriage-return progress frames only make sense on a real terminal;
	// when stdout is piped or redirected they would otherwise flood the output
	// with one frame per update.
	if r.format != "terminal" || !r.tty {
		return
	}
	percent := float64(current) / float64(total) * 100
	width := 30
	completed := int(float64(width) * (float64(current) / float64(total)))
	if completed > width {
		completed = width
	}
	bar := strings.Repeat("█", completed) + strings.Repeat("░", width-completed)
	fmt.Printf("\r  %s [%s] %3.0f%% (%d/%d)   ", dim.Sprint(label), accent.Sprint(bar), percent, current, total)
	if current == total {
		fmt.Println()
	}
}

func (r *Renderer) SubdomainTable(results []SubdomainResult) {
	if r.isQuiet() {
		return
	}
	var displayResults []SubdomainResult
	for _, s := range results {
		if s.Resolved || len(s.DeadCNAMEs) > 0 || r.verbose {
			displayResults = append(displayResults, s)
		}
	}

	if len(displayResults) == 0 {
		dim.Println("  no subdomains discovered")
		return
	}

	crtsh := 0
	wordlist := 0
	san := 0
	for _, s := range displayResults {
		switch s.Source {
		case "crtsh":
			crtsh++
		case "wordlist":
			wordlist++
		case "san":
			san++
		}
	}

	dim.Printf("  sources: ")
	accent.Printf("crt.sh=%d  ", crtsh)
	dim.Printf("wordlist=%d  san=%d\n\n", wordlist, san)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	for _, s := range displayResults {
		ip := "—"
		if len(s.IPs) > 0 {
			ip = s.IPs[0]
		}

		status := dim.Sprint("DEAD")
		fqdnStr := dim.Sprint(s.FQDN)
		if s.Resolved {
			status = green.Sprint("LIVE")
			fqdnStr = s.FQDN
		}

		sourceColor := dim.Sprint(s.Source)
		switch s.Source {
		case "crtsh":
			sourceColor = accentDim.Sprint("crt.sh")
		case "san":
			sourceColor = greenDim.Sprint("san")
		case "mutation":
			sourceColor = orange.Sprint("mutate")
		}

		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", fqdnStr, ip, sourceColor, status)

		for _, cname := range s.DeadCNAMEs {
			fmt.Fprintf(w, "  \tCNAME → %s\t\t\n", dim.Sprint(cname))
		}
	}
	_ = w.Flush()
	fmt.Println()
}

func (r *Renderer) ProbeTable(results []ProbeResult) {
	if r.isQuiet() {
		return
	}
	var displayResults []ProbeResult
	for _, p := range results {
		if p.IsAlive || r.verbose {
			displayResults = append(displayResults, p)
		}
	}

	live := 0
	for _, p := range results {
		if p.IsAlive {
			live++
		}
	}
	dim.Printf("  live: %d / %d\n\n", live, len(results))

	for _, p := range displayResults {
		var codeStr string
		var codeColor string
		if p.IsAlive {
			codeStr = fmt.Sprintf("%d", p.StatusCode)
			codeColor = greenDim.Sprint(codeStr)
			if p.StatusCode >= 400 {
				codeColor = redDim.Sprint(codeStr)
			} else if p.StatusCode >= 300 {
				codeColor = orange.Sprint(codeStr)
			}
		} else {
			codeColor = redDim.Sprint("DEAD")
		}

		server := p.Server
		if server == "" {
			server = "—"
		}
		if len(p.Technologies) > 0 {
			server = fmt.Sprintf("%s [%s]", server, strings.Join(p.Technologies, ", "))
		}
		url := p.URL
		if url == "" {
			url = p.FQDN
		}

		accentDim.Printf("  [+] %s (%s, %s)\n", url, codeColor, server)
	}
	fmt.Println()
}

func (r *Renderer) TLSTable(results []TLSResult) {
	if r.isQuiet() {
		return
	}
	var displayResults []TLSResult
	for _, t := range results {
		if t.Supported || r.verbose {
			displayResults = append(displayResults, t)
		}
	}

	for _, t := range displayResults {
		if !t.Supported {
			redDim.Printf("  [-] %s — TLS failed: %s\n", t.Hostname, t.Error)
			continue
		}

		expiryStr := fmt.Sprintf("%d days", t.DaysUntilExpiry)
		expiryColor := greenDim.Sprint(expiryStr)
		if t.Expired {
			expiryColor = red.Sprint("EXPIRED")
		} else if t.ExpiringSoon {
			expiryColor = orange.Sprint(expiryStr)
		}

		selfSignedFlag := ""
		if t.SelfSigned {
			selfSignedFlag = red.Sprint(" self-signed")
		}

		accentDim.Printf("  [+] %s — %s, expires %s%s\n", t.Hostname, t.Protocol, expiryColor, selfSignedFlag)
	}
	fmt.Println()
}

func (r *Renderer) HeadersTable(results []HeaderResult) {
	if r.isQuiet() {
		return
	}
	var displayResults []HeaderResult
	for _, hr := range results {
		if hr.Success || r.verbose {
			displayResults = append(displayResults, hr)
		}
	}

	for _, hr := range displayResults {
		if !hr.Success {
			redDim.Printf("  [-] %s — header check failed\n", hr.URL)
			continue
		}

		missing := []string{}
		for _, h := range []string{"strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"} {
			if val, ok := hr.Headers[h]; !ok || val == "" {
				missing = append(missing, shortName(h))
			}
		}

		msg := fmt.Sprintf("  [+] %s", hr.URL)
		if len(missing) > 0 {
			dim.Printf("%s — missing: %s\n", msg, strings.Join(missing, ", "))
		} else {
			accentDim.Printf("%s — all headers present\n", msg)
		}
	}
	fmt.Println()
}

func (r *Renderer) FindingsBlock(phase string, findings []Finding) {
	if r.isQuiet() {
		return
	}
	if len(findings) == 0 {
		dim.Printf("  [*] no findings from %s\n", phase)
		return
	}

	for _, f := range findings {
		r.printFinding(f)
	}
}

func (r *Renderer) printFinding(f Finding) {
	sev := f.Severity
	prefix := "[*]"
	switch sev {
	case Critical:
		red.Printf("  [!] %s — %s\n", f.Title, f.AffectedAsset)
	case High:
		orange.Printf("  [!] %s — %s\n", f.Title, f.AffectedAsset)
	case Medium:
		color.New(color.FgYellow).Printf("  [!] %s — %s\n", f.Title, f.AffectedAsset)
	default:
		dim.Printf("  %s %s — %s\n", prefix, f.Title, f.AffectedAsset)
	}
	if f.Status != "" {
		dim.Printf("       lifecycle: %s\n", f.Status)
	}
	if f.Remediation != "" {
		dim.Printf("       fix: %s\n", f.Remediation)
	}
}

func (r *Renderer) TechTable(results []TechResult) {
	if r.isQuiet() {
		return
	}
	if len(results) == 0 {
		dim.Println("  [*] no application stacks detected")
		return
	}

	for _, tr := range results {
		stackStr := accentDim.Sprint(tr.Stack)
		if tr.Version != "" {
			stackStr = accentDim.Sprint(tr.Stack + " " + tr.Version)
		}

		detected := ""
		if tr.DetectedBy != "" {
			detected = fmt.Sprintf(" (%s)", dim.Sprint(tr.DetectedBy))
		}

		components := ""
		if len(tr.Components) > 0 {
			components = fmt.Sprintf("  [%s]", strings.Join(tr.Components, ", "))
		}

		white.Printf("  [+] %s%s\n", stackStr, detected)
		dim.Printf("      %s%s\n", tr.URL, components)

		for _, f := range tr.Findings {
			r.printFinding(f)
		}
	}
	fmt.Println()
}

func (r *Renderer) ChainTable(chains []ExploitChain) {
	if r.isQuiet() {
		return
	}
	if len(chains) == 0 {
		dim.Println("  [*] no exploit chains assembled")
		return
	}

	for _, c := range chains {
		white.Printf("  [+] %s [%s] (score %d)\n", c.Name, chainSeverityColor(c.Severity), c.Score)
		dim.Printf("      %s\n", c.Summary)
		for _, s := range c.Steps {
			fmt.Printf("      %d. %s — %s\n", s.Order, chainSeverityColor(s.Severity), dim.Sprint(s.FindingTitle))
			dim.Printf("          asset: %s\n", s.AffectedAsset)
			if s.Technique != "" {
				dim.Printf("          technique: %s\n", s.Technique)
			}
		}
		fmt.Println()
	}
}

// chainSeverityColor renders a severity label with its colour.
func chainSeverityColor(sev string) string {
	switch sev {
	case Critical:
		return red.Sprint(sev)
	case High:
		return orange.Sprint(sev)
	case Medium:
		return color.New(color.FgYellow).Sprint(sev)
	}
	return dim.Sprint(sev)
}

// ExploitResultsBlock renders the outcome of the PoC/exploitation layer for
// one phase. Each result is shown with its lifecycle state, module, target
// and evidence summary.
func (r *Renderer) ExploitResultsBlock(results []ExploitResult) {
	if r.isQuiet() {
		return
	}
	if len(results) == 0 {
		dim.Println("  [*] no exploit results")
		return
	}
	for _, res := range results {
		status := exploitStatusColor(res.Status)
		marker := "[*]"
		switch res.Status {
		case "exploited", "evidence_captured":
			marker = "[!]"
		case "exploit_failed", "validation_failed", "safety_blocked", "authorization_required":
			marker = "[-]"
		}
		white.Printf("  %s %s — %s\n", marker, status, res.FindingTitle)
		dim.Printf("       module: %s (%s)\n", res.ModuleID, res.Risk)
		dim.Printf("       target: %s\n", res.Target)
		for _, ev := range res.Evidence {
			accentDim.Printf("       evidence: %s\n", ev)
		}
		if res.Error != "" {
			redDim.Printf("       error: %s\n", res.Error)
		}
	}
	fmt.Println()
}

// exploitStatusColor renders an exploitation lifecycle state with a colour.
func exploitStatusColor(status string) string {
	switch status {
	case "exploited", "evidence_captured":
		return green.Sprint(status)
	case "exploitable":
		return accent.Sprint(status)
	case "exploit_failed", "validation_failed", "safety_blocked":
		return red.Sprint(status)
	case "authorization_required":
		return orange.Sprint(status)
	case "dry_run", "validated":
		return accentDim.Sprint(status)
	}
	return dim.Sprint(status)
}

func (r *Renderer) OSINTTable(results []OSINTResult) {
	if r.isQuiet() {
		return
	}
	if len(results) == 0 {
		dim.Println("  [*] no OSINT data discovered")
		return
	}

	for _, res := range results {
		prefix := "[*]"
		val := res.Value
		if len(val) > 60 {
			val = val[:57] + "..."
		}

		switch res.Category {
		case "email":
			accentDim.Printf("  [+] %s (%s)\n", val, res.Source)
		case "phone":
			orange.Printf("  [+] %s (%s)\n", val, res.Source)
		case "employee":
			green.Printf("  [+] Employee: %s (%s)\n", val, res.Source)
		case "org":
			white.Printf("  %s Org: %s (%s)\n", prefix, val, res.Source)
		default:
			dim.Printf("  %s %s: %s (%s)\n", prefix, res.Category, val, res.Source)
		}
	}
	fmt.Println()
}

func (r *Renderer) Summary(report *Report) {
	// Filter out "not found" or failed items if not running in verbose mode
	if !r.verbose {
		var filteredSubs []SubdomainResult
		for _, s := range report.Subdomains {
			if s.Resolved || len(s.DeadCNAMEs) > 0 {
				filteredSubs = append(filteredSubs, s)
			}
		}
		report.Subdomains = filteredSubs

		var filteredProbes []ProbeResult
		for _, p := range report.ProbeResults {
			if p.IsAlive {
				filteredProbes = append(filteredProbes, p)
			}
		}
		report.ProbeResults = filteredProbes

		var filteredTLS []TLSResult
		for _, t := range report.TLSResults {
			if t.Supported {
				filteredTLS = append(filteredTLS, t)
			}
		}
		report.TLSResults = filteredTLS

		var filteredHeaders []HeaderResult
		for _, h := range report.HeaderResults {
			if h.Success {
				filteredHeaders = append(filteredHeaders, h)
			}
		}
		report.HeaderResults = filteredHeaders
	}

	if r.format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %s\n", err)
		}
		return
	}

	if r.format == "html" {
		r.renderHTML(report)
		return
	}

	if r.format == "markdown" {
		r.renderMarkdown(report)
		return
	}

	fmt.Println()
	fmt.Println()
	accent.Println("  [+] SUMMARY")

	counts := map[string]int{Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0}
	for _, f := range report.Findings {
		if _, ok := counts[f.Severity]; ok {
			counts[f.Severity]++
		}
	}

	riskScore := computeRisk(counts)
	riskStr := fmt.Sprintf("%d/100", riskScore)
	riskDisplay := greenDim.Sprint(riskStr)
	if riskScore >= 67 {
		riskDisplay = red.Sprint(riskStr)
	} else if riskScore >= 34 {
		riskDisplay = orange.Sprint(riskStr)
	}

	liveCount := 0
	for _, p := range report.ProbeResults {
		if p.IsAlive {
			liveCount++
		}
	}

	fmt.Printf("  target      %s\n", white.Sprint(report.Target))
	fmt.Printf("  duration    %s\n", dim.Sprint(report.Duration.Round(time.Millisecond).String()))
	fmt.Printf("  subdomains  %s\n", dim.Sprint(fmt.Sprintf("%d discovered, %d live", len(report.Subdomains), liveCount)))
	fmt.Printf("  risk score  %s\n", riskDisplay)
	fmt.Println()

	findingStr := fmt.Sprintf("  findings    CRIT:%d  HIGH:%d  MED:%d  LOW:%d  INFO:%d",
		counts[Critical], counts[High], counts[Medium], counts[Low], counts[Info])
	dim.Println(findingStr)

	if len(report.Chains) > 0 {
		top := report.Chains[0]
		fmt.Printf("  chains      %d paths, top: %s [%s]\n",
			len(report.Chains), top.Name, chainSeverityColor(top.Severity))
	} else {
		dim.Println("  chains      0 exploit paths")
	}

	exploited := 0
	for _, e := range report.ExploitResults {
		if e.Status == "evidence_captured" || e.Status == "exploited" {
			exploited++
		}
	}
	if len(report.ExploitResults) > 0 {
		fmt.Printf("  exploit     %d runs, %d proven\n", len(report.ExploitResults), exploited)
	} else {
		dim.Println("  exploit     0 PoC runs (enable the exploit module)")
	}

	if counts[Critical]+counts[High] > 0 {
		fmt.Println()
		red.Println("  [!] HIGH PRIORITY FINDINGS")
		for _, f := range report.Findings {
			if f.Severity == Critical || f.Severity == High {
				r.printFinding(f)
			}
		}
	}

	fmt.Println()
}

func (r *Renderer) renderHTML(report *Report) {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(htmlReportTemplate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing HTML template: %s\n", err)
		return
	}

	counts := map[string]int{Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0}
	for _, f := range report.Findings {
		if _, ok := counts[f.Severity]; ok {
			counts[f.Severity]++
		}
	}
	riskScore := computeRisk(counts)

	liveCount := 0
	for _, p := range report.ProbeResults {
		if p.IsAlive {
			liveCount++
		}
	}

	data := struct {
		Report      *Report
		Counts      map[string]int
		RiskScore   int
		LiveCount   int
		CompanyName string
		BuiltIn     string
	}{
		Report:      report,
		Counts:      counts,
		RiskScore:   riskScore,
		LiveCount:   liveCount,
		CompanyName: CompanyName,
		BuiltIn:     BuiltIn,
	}

	if err := tmpl.Execute(os.Stdout, data); err != nil {
		fmt.Fprintf(os.Stderr, "Error rendering HTML report: %s\n", err)
	}
}

func shortName(header string) string {
	m := map[string]string{
		"strict-transport-security": "HSTS",
		"content-security-policy":   "CSP",
		"x-frame-options":           "XFO",
		"x-content-type-options":    "XCTO",
		"referrer-policy":           "RP",
		"permissions-policy":        "PP",
	}
	if v, ok := m[header]; ok {
		return v
	}
	return header
}

func computeRisk(counts map[string]int) int {
	score := counts[Critical]*20 + counts[High]*10 + counts[Medium]*5 + counts[Low]*2
	if score > 100 {
		return 100
	}
	return score
}

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ANANSI Report: {{.Report.Target}}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #000000;
            --surface: #050505;
            --border: rgba(171, 181, 192, 0.12);
            --accent: #66B870;
            --accent-rgb: 102, 184, 112;
            --green: #66B870;
            --yellow: #fbbf24;
            --red: #ef4444;
            --text: #EEF0EE;
            --text-dim: rgba(238, 240, 238, 0.40);
        }
        body {
            font-family: 'Outfit', sans-serif;
            background: var(--bg);
            color: var(--text);
            padding: 2rem;
            margin: 0;
            background-image: radial-gradient(circle at 0% 0%, rgba(102, 184, 112, 0.05) 0%, transparent 50%),
                              radial-gradient(circle at 100% 100%, rgba(102, 184, 112, 0.03) 0%, transparent 50%);
            background-attachment: fixed;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }
        h1 {
            font-size: 2.2rem;
            font-weight: 800;
            letter-spacing: -0.04em;
            background: linear-gradient(to right, var(--accent), #34d399);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin: 0;
        }
        .meta {
            text-align: right;
            font-size: 0.9rem;
            color: var(--text-dim);
        }
        .meta strong { color: var(--text); }
        .grid-layout {
            display: grid;
            grid-template-columns: 3fr 1fr;
            gap: 2rem;
        }
        .cards-column {
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            backdrop-filter: blur(12px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        .card h2 {
            font-size: 1.3rem;
            font-weight: 600;
            margin-top: 0;
            margin-bottom: 1rem;
            color: var(--accent);
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.5rem;
        }
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
        }
        .stat-box {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }
        .stat-box .num {
            font-size: 1.8rem;
            font-weight: 800;
        }
        .stat-box .lbl {
            font-size: 0.75rem;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 0.2rem;
        }
        .risk-card {
            text-align: center;
        }
        .risk-ring {
            position: relative;
            width: 100px;
            height: 100px;
            margin: 0 auto 1rem auto;
            border-radius: 50%;
            background: conic-gradient(var(--accent) calc({{.RiskScore}} * 1%), rgba(238, 240, 238, 0.05) 0);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .risk-ring::after {
            content: '';
            position: absolute;
            width: 86px;
            height: 86px;
            border-radius: 50%;
            background: #050505;
        }
        .risk-score {
            position: absolute;
            font-size: 1.5rem;
            font-weight: 800;
            z-index: 10;
        }
        .finding-badge, .badge {
            font-size: 0.75rem;
            font-weight: bold;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            text-transform: uppercase;
        }
        .finding-badge.critical, .badge.critical { background: rgba(239, 68, 68, 0.15); color: var(--red); }
        .finding-badge.high, .badge.high { background: rgba(245, 158, 11, 0.15); color: var(--yellow); }
        .finding-badge.medium, .badge.medium { background: rgba(234, 179, 8, 0.15); color: #eab308; }
        .finding-badge.low, .badge.low { background: rgba(59, 130, 246, 0.15); color: var(--blue); }
        .finding-badge.info, .badge.info { background: rgba(156, 163, 175, 0.15); color: var(--text-dim); }

        .finding-item {
            border-left: 4px solid var(--border);
            background: rgba(255, 255, 255, 0.01);
            border-radius: 0 8px 8px 0;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        .finding-item.critical { border-left-color: var(--red); }
        .finding-item.high { border-left-color: var(--yellow); }
        .finding-item.medium { border-left-color: #eab308; }
        .finding-item.low { border-left-color: var(--blue); }
        .finding-item.info { border-left-color: var(--text-dim); }

        .finding-hdr {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        .finding-title { font-weight: 600; font-size: 1.05rem; }
        .finding-asset { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--accent); margin-bottom: 0.4rem; }
        .finding-desc { font-size: 0.9rem; color: rgba(238, 240, 238, 0.70); }
        .chain-step {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 0.5rem;
            padding: 0.45rem 0 0.1rem 0;
            margin-top: 0.5rem;
            border-top: 1px dashed var(--border);
        }
        .chain-detail { font-size: 0.8rem; color: rgba(238, 240, 238, 0.60); margin-left: 1.4rem; }
        .finding-evidence {
            background: #0d0d0d;
            border: 1px solid var(--border);
            padding: 0.75rem;
            border-radius: 6px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: #34d399;
            white-space: pre-wrap;
            margin-top: 0.5rem;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            text-align: left;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
            font-size: 0.88rem;
        }
        th {
            font-size: 0.75rem;
            text-transform: uppercase;
            color: var(--text-dim);
            letter-spacing: 0.05em;
        }
        tr:hover td { background: rgba(255, 255, 255, 0.01); }
        .badge-live { background: rgba(16, 185, 129, 0.15); color: var(--green); padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
        .badge-dead { background: rgba(239, 68, 68, 0.15); color: var(--red); padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; }
        .dot.green { background: var(--green); }
        .dot.red { background: var(--red); }
    </style>
</head>
<body>
<div class="container">
    <header>
        <div class="logo-section">
            <h1>ANANSI SCAN REPORT</h1>
            <p>Attack Surface Intelligence Engine — {{.CompanyName}}</p>
        </div>
        <div class="meta">
            <p>Target: <strong>{{.Report.Target}}</strong></p>
            <p>Duration: <strong>{{.Report.Duration.Round 1000000}}</strong></p>
            <p>Time: <strong>{{.Report.StartedAt.UTC.Format "2006-01-02 15:04:05 UTC"}}</strong></p>
        </div>
    </header>

    <div class="grid-layout">
        <div class="cards-column">
            <!-- Findings Summary -->
            <div class="card">
                <h2>Vulnerability & Finding Log</h2>
                {{if .Report.Findings}}
                    {{range .Report.Findings}}
                        <div class="finding-item {{html (lower .Severity)}}">
                            <div class="finding-hdr">
                                <span class="finding-title">{{.Title}}</span>
                                <span class="finding-badge {{html (lower .Severity)}}">{{.Severity}}</span>
                            </div>
                            <div class="finding-asset">{{.AffectedAsset}}</div>
                            <div class="finding-desc">{{.Description}}</div>
                            {{if .Evidence}}
                                <div class="finding-evidence">{{.Evidence}}</div>
                            {{end}}
                        </div>
                    {{end}}
                {{else}}
                    <p style="color: var(--text-dim);">No vulnerability findings identified during the scan.</p>
                {{end}}
            </div>

            <!-- Subdomains Table -->
            <div class="card">
                <h2>Subdomains ({{len .Report.Subdomains}})</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Subdomain</th>
                            <th>Resolved IP</th>
                            <th>Source</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Report.Subdomains}}
                            <tr>
                                <td class="mono">{{.FQDN}}</td>
                                <td class="mono">{{if .IPs}}{{index .IPs 0}}{{else}}—{{end}}</td>
                                <td>{{.Source}}</td>
                                <td>
                                    {{if .Resolved}}
                                        <span class="badge-live">LIVE</span>
                                    {{else}}
                                        <span class="badge-dead">DEAD</span>
                                    {{end}}
                                </td>
                            </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>

            <!-- Probes Table -->
            <div class="card">
                <h2>HTTP Probes ({{.LiveCount}} / {{len .Report.ProbeResults}})</h2>
                <table>
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Code</th>
                            <th>Server / Technologies</th>
                            <th>Title</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Report.ProbeResults}}
                            <tr>
                                <td class="mono"><a href="{{if .URL}}{{.URL}}{{else}}http://{{.FQDN}}{{end}}" target="_blank" style="color: var(--accent); text-decoration: none; border-bottom: 1px dotted rgba(102, 184, 112, 0.3);">{{if .URL}}{{.URL}}{{else}}{{.FQDN}}{{end}}</a></td>
                                <td>
                                    {{if .IsAlive}}
                                        <span style="color: {{if ge .StatusCode 400}}var(--red){{else if ge .StatusCode 300}}var(--yellow){{else}}var(--green){{end}}; font-weight: bold;">{{.StatusCode}}</span>
                                    {{else}}
                                        <span style="color: var(--red); font-weight: bold;">DEAD</span>
                                    {{end}}
                                </td>
                                <td>
                                    {{if .Server}}{{.Server}}{{else}}—{{end}}
                                    {{if .Technologies}}
                                        <span style="color: var(--text-dim); font-size: 0.8rem;">[{{range $i, $t := .Technologies}}{{if $i}}, {{end}}{{$t}}{{end}}]</span>
                                    {{end}}
                                </td>
                                <td>{{if .Title}}{{.Title}}{{else}}—{{end}}</td>
                            </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>

            <!-- TLS Table -->
            <div class="card">
                <h2>TLS Configuration ({{len .Report.TLSResults}})</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Hostname</th>
                            <th>Protocol</th>
                            <th>Expiry</th>
                            <th>Issuer</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Report.TLSResults}}
                            <tr>
                                <td class="mono">{{.Hostname}}</td>
                                <td class="mono">{{if .Supported}}{{.Protocol}}{{else}}—{{end}}</td>
                                <td>
                                    {{if .Supported}}
                                        <span style="color: {{if .Expired}}var(--red){{else if .ExpiringSoon}}var(--yellow){{else}}var(--green){{end}}; font-weight: bold;">
                                            {{if .Expired}}EXPIRED{{else}}{{.DaysUntilExpiry}} days{{end}}
                                        </span>
                                    {{else}}
                                        <span style="color: var(--red); font-weight: bold;">FAILED</span>
                                    {{end}}
                                </td>
                                <td>{{if .Supported}}{{.Issuer}}{{else}}<span style="color: var(--text-dim); font-size: 0.8rem;">{{.Error}}</span>{{end}}</td>
                            </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>

            <!-- Headers Audit Table -->
            <div class="card">
                <h2>Security Headers</h2>
                <table>
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>HSTS</th>
                            <th>CSP</th>
                            <th>XFO</th>
                            <th>XCTO</th>
                            <th>RP</th>
                            <th>PP</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Report.HeaderResults}}
                            <tr>
                                <td class="mono" style="font-size: 0.8rem;">{{.URL}}</td>
                                {{if .Success}}
                                    <td><span class="dot {{if index .Headers "strict-transport-security"}}green{{else}}red{{end}}"></span></td>
                                    <td><span class="dot {{if index .Headers "content-security-policy"}}green{{else}}red{{end}}"></span></td>
                                    <td><span class="dot {{if index .Headers "x-frame-options"}}green{{else}}red{{end}}"></span></td>
                                    <td><span class="dot {{if index .Headers "x-content-type-options"}}green{{else}}red{{end}}"></span></td>
                                    <td><span class="dot {{if index .Headers "referrer-policy"}}green{{else}}red{{end}}"></span></td>
                                    <td><span class="dot {{if index .Headers "permissions-policy"}}green{{else}}red{{end}}"></span></td>
                                {{else}}
                                    <td colspan="6" style="color: var(--red); font-size: 0.8rem; text-align: center;">FAILED</td>
                                {{end}}
                            </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
            <!-- Tech-Stack Deep Audit -->
            <div class="card">
                <h2>Tech-Stack Deep Audit ({{len .Report.TechResults}})</h2>
                {{if .Report.TechResults}}
                    {{range .Report.TechResults}}
                        <div style="margin-bottom: 1rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border);">
                            <div style="font-weight: 600; color: var(--accent);">
                                {{.Stack}}{{if .Version}} <span class="mono" style="font-size: 0.85rem;">{{.Version}}</span>{{end}}
                            </div>
                            <div class="finding-asset">{{.URL}}</div>
                            {{if .DetectedBy}}<div style="font-size: 0.75rem; color: var(--text-dim);">via {{.DetectedBy}}</div>{{end}}
                            {{if .Components}}
                                <div class="mono" style="font-size: 0.78rem; color: var(--text-dim);">{{range $i, $c := .Components}}{{if $i}}, {{end}}{{$c}}{{end}}</div>
                            {{end}}
                            {{range .Findings}}
                                <div class="finding-item {{html (lower .Severity)}}" style="margin-top: 0.5rem;">
                                    <div class="finding-hdr">
                                        <span class="finding-title">{{.Title}}</span>
                                        <span class="finding-badge {{html (lower .Severity)}}">{{.Severity}}</span>
                                    </div>
                                    <div class="finding-asset">{{.AffectedAsset}}</div>
                                    <div class="finding-desc">{{.Description}}</div>
                                    {{if .Evidence}}<div class="finding-evidence">{{.Evidence}}</div>{{end}}
                                    {{if .Remediation}}<div style="font-size: 0.85rem; margin-top: 0.4rem; color: var(--text-dim);">Fix: {{.Remediation}}</div>{{end}}
                                </div>
                            {{end}}
                        </div>
                    {{end}}
                {{else}}
                    <p style="color: var(--text-dim);">No application stacks detected.</p>
                {{end}}
            </div>

            <!-- Exploit Chains -->
            <div class="card">
                <h2>Exploit Chains ({{len .Report.Chains}})</h2>
                {{if .Report.Chains}}
                    {{range .Report.Chains}}
                        <div style="margin-bottom: 1rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border);">
                            <div class="finding-hdr">
                                <span class="finding-title">{{.Name}}</span>
                                <span class="finding-badge {{html (lower .Severity)}}">{{.Severity}}</span>
                            </div>
                            <div class="finding-desc">{{.Summary}}</div>
                            {{range .Steps}}
                                <div class="chain-step">
                                    <span class="mono" style="color: var(--text-dim);">{{.Order}}.</span>
                                    <span style="flex: 1; font-weight: 600;">{{.Class}}</span>
                                    <span class="finding-badge {{html (lower .Severity)}}">{{.Severity}}</span>
                                </div>
                                <div class="chain-detail">{{.FindingTitle}} <span class="mono" style="color: var(--accent);">{{.AffectedAsset}}</span></div>
                                {{if .Technique}}<div class="chain-detail" style="font-style: italic;">Technique: {{.Technique}}</div>{{end}}
                            {{end}}
                        </div>
                    {{end}}
                {{else}}
                    <p style="color: var(--text-dim);">No exploit chains assembled.</p>
                {{end}}
            </div>

            <!-- Exploit Results -->
            <div class="card">
                <h2>Exploit Results ({{len .Report.ExploitResults}})</h2>
                {{if .Report.ExploitResults}}
                    {{range .Report.ExploitResults}}
                        <div class="finding-item {{if eq .Status "evidence_captured"}}high{{else if eq .Status "exploit_failed"}}high{{else if eq .Status "authorization_required"}}low{{else}}info{{end}}">
                            <div class="finding-hdr">
                                <span class="finding-title">{{.FindingTitle}}</span>
                                <span class="finding-badge {{if eq .Status "evidence_captured"}}high{{else if eq .Status "exploit_failed"}}high{{else if eq .Status "authorization_required"}}low{{else}}info{{end}}">{{.Status}}</span>
                            </div>
                            <div class="finding-asset mono">{{.ModuleID}} — {{.Target}}</div>
                            {{if .Evidence}}
                                <div class="finding-evidence">{{range $i, $e := .Evidence}}{{if $i}}
{{end}}{{$e}}{{end}}</div>
                            {{end}}
                            {{if .Error}}<div style="font-size: 0.8rem; color: var(--text-dim); margin-top: 0.4rem;">{{.Error}}</div>{{end}}
                        </div>
                    {{end}}
                {{else}}
                    <p style="color: var(--text-dim);">No PoC/exploitation runs performed.</p>
                {{end}}
            </div>
        </div>

        <div class="sidebar">
            <div class="card risk-card">
                <h2>Risk Score</h2>
                <div class="risk-ring">
                    <div class="risk-score">{{.RiskScore}}</div>
                </div>
                <div style="font-size: 0.95rem; color: var(--text-dim); margin-top: 1rem;">
                    Risk Level: 
                    <span style="color: {{if ge .RiskScore 67}}var(--red){{else if ge .RiskScore 34}}var(--yellow){{else}}var(--green){{end}}; font-weight: bold;">
                        {{if ge .RiskScore 67}}Critical/High{{else if ge .RiskScore 34}}Medium{{else}}Low{{end}}
                    </span>
                </div>
            </div>

            <div class="card">
                <h2>Finding Summary</h2>
                <ul style="list-style: none; padding: 0; display: flex; flex-direction: column; gap: 0.8rem; font-size: 0.95rem;">
                    <li style="display: flex; justify-content: space-between;"><span>Critical</span> <span class="badge critical">{{index .Counts "CRITICAL"}}</span></li>
                    <li style="display: flex; justify-content: space-between;"><span>High</span> <span class="badge high">{{index .Counts "HIGH"}}</span></li>
                    <li style="display: flex; justify-content: space-between;"><span>Medium</span> <span class="badge medium">{{index .Counts "MEDIUM"}}</span></li>
                    <li style="display: flex; justify-content: space-between;"><span>Low</span> <span class="badge low">{{index .Counts "LOW"}}</span></li>
                    <li style="display: flex; justify-content: space-between;"><span>Info</span> <span class="badge info">{{index .Counts "INFO"}}</span></li>
                    <li style="display: flex; justify-content: space-between;"><span>Exploit Chains</span> <span class="badge info">{{len .Report.Chains}}</span></li>
                    <li style="display: flex; justify-content: space-between;"><span>Exploit Runs</span> <span class="badge info">{{len .Report.ExploitResults}}</span></li>
                </ul>
            </div>
        </div>
    </div>
</div>
</body>
</html>`

func (r *Renderer) renderMarkdown(report *Report) {
	fmt.Println("# ANANSI SCAN REPORT")
	fmt.Println()
	fmt.Printf("## Target: `%s`\n", report.Target)
	fmt.Printf("- **Start Time:** %s\n", report.StartedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("- **Duration:** %s\n", report.Duration.Round(time.Millisecond).String())
	fmt.Println()

	// Risk Score
	counts := map[string]int{Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0}
	for _, f := range report.Findings {
		if _, ok := counts[f.Severity]; ok {
			counts[f.Severity]++
		}
	}
	riskScore := computeRisk(counts)
	fmt.Printf("## Summary\n")
	fmt.Printf("- **Risk Score:** %d/100\n", riskScore)
	fmt.Printf("- **Findings:** Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d\n",
		counts[Critical], counts[High], counts[Medium], counts[Low], counts[Info])
	fmt.Printf("- **Exploit Chains:** %d\n", len(report.Chains))
	fmt.Println()

	// Vulnerability Log
	fmt.Println("## Vulnerability & Finding Log")
	if len(report.Findings) == 0 {
		fmt.Println("No vulnerability findings identified during the scan.")
	} else {
		for _, f := range report.Findings {
			fmt.Printf("### [%s] %s\n", f.Severity, f.Title)
			fmt.Printf("- **Affected Asset:** `%s`\n", f.AffectedAsset)
			if f.Description != "" {
				fmt.Printf("- **Description:** %s\n", f.Description)
			}
			if f.Evidence != "" {
				fmt.Printf("- **Evidence:**\n  ```\n  %s\n  ```\n", strings.ReplaceAll(f.Evidence, "\n", "\n  "))
			}
			if f.Remediation != "" {
				fmt.Printf("- **Remediation:** %s\n", f.Remediation)
			}
			fmt.Println()
		}
	}
	fmt.Println()

	// Subdomains Table
	fmt.Println("## Subdomains")
	fmt.Println("| Subdomain | Resolved IP | Source | Status |")
	fmt.Println("|-----------|-------------|--------|--------|")
	for _, s := range report.Subdomains {
		ip := "—"
		if len(s.IPs) > 0 {
			ip = s.IPs[0]
		}
		status := "DEAD"
		if s.Resolved {
			status = "LIVE"
		}
		fmt.Printf("| `%s` | `%s` | %s | %s |\n", s.FQDN, ip, s.Source, status)
	}
	fmt.Println()

	// Probes Table
	liveProbes := 0
	for _, p := range report.ProbeResults {
		if p.IsAlive {
			liveProbes++
		}
	}
	fmt.Printf("## HTTP Probes (%d / %d)\n", liveProbes, len(report.ProbeResults))
	fmt.Println("| URL | Code | Server / Technologies | Title |")
	fmt.Println("|-----|------|-----------------------|-------|")
	for _, p := range report.ProbeResults {
		status := "DEAD"
		if p.IsAlive {
			status = fmt.Sprintf("%d", p.StatusCode)
		}
		serverInfo := "—"
		if p.Server != "" {
			serverInfo = p.Server
		}
		if len(p.Technologies) > 0 {
			serverInfo = fmt.Sprintf("%s [%s]", serverInfo, strings.Join(p.Technologies, ", "))
		}
		title := "—"
		if p.Title != "" {
			title = p.Title
		}
		urlStr := p.URL
		if urlStr == "" {
			urlStr = p.FQDN
		}
		fmt.Printf("| %s | %s | %s | %s |\n", urlStr, status, serverInfo, title)
	}
	fmt.Println()

	// TLS Table
	fmt.Println("## TLS Configuration")
	fmt.Println("| Hostname | Protocol | Expiry | Issuer |")
	fmt.Println("|----------|----------|--------|--------|")
	for _, t := range report.TLSResults {
		if t.Supported {
			expiry := fmt.Sprintf("%d days", t.DaysUntilExpiry)
			if t.Expired {
				expiry = "EXPIRED"
			}
			fmt.Printf("| `%s` | %s | %s | %s |\n", t.Hostname, t.Protocol, expiry, t.Issuer)
		} else {
			fmt.Printf("| `%s` | — | FAILED | %s |\n", t.Hostname, t.Error)
		}
	}
	fmt.Println()

	// Headers Table
	fmt.Println("## Security Headers")
	fmt.Println("| URL | HSTS | CSP | XFO | XCTO | RP | PP |")
	fmt.Println("|-----|------|-----|-----|------|----|----|")
	for _, h := range report.HeaderResults {
		if h.Success {
			hsts := "❌"
			if h.Headers["strict-transport-security"] != "" {
				hsts = "✅"
			}
			csp := "❌"
			if h.Headers["content-security-policy"] != "" {
				csp = "✅"
			}
			xfo := "❌"
			if h.Headers["x-frame-options"] != "" {
				xfo = "✅"
			}
			xcto := "❌"
			if h.Headers["x-content-type-options"] != "" {
				xcto = "✅"
			}
			rp := "❌"
			if h.Headers["referrer-policy"] != "" {
				rp = "✅"
			}
			pp := "❌"
			if h.Headers["permissions-policy"] != "" {
				pp = "✅"
			}
			fmt.Printf("| `%s` | %s | %s | %s | %s | %s | %s |\n", h.URL, hsts, csp, xfo, xcto, rp, pp)
		} else {
			fmt.Printf("| `%s` | FAILED | | | | | |\n", h.URL)
		}
	}
	fmt.Println()

	// Tech-Stack Deep Audit
	fmt.Println("## Tech-Stack Deep Audit")
	if len(report.TechResults) == 0 {
		fmt.Println("No application stacks detected.")
	} else {
		for _, tr := range report.TechResults {
			version := ""
			if tr.Version != "" {
				version = " " + tr.Version
			}
			fmt.Printf("### %s%s\n", tr.Stack, version)
			fmt.Printf("- **URL:** `%s`\n", tr.URL)
			if tr.DetectedBy != "" {
				fmt.Printf("- **Version via:** %s\n", tr.DetectedBy)
			}
			if len(tr.Components) > 0 {
				fmt.Printf("- **Components:** `%s`\n", strings.Join(tr.Components, ", "))
			}
			for _, f := range tr.Findings {
				fmt.Printf("- **[%s] %s** — `%s`\n", f.Severity, f.Title, f.AffectedAsset)
				if f.Evidence != "" {
					fmt.Printf("  - Evidence: `%s`\n", f.Evidence)
				}
				if f.Remediation != "" {
					fmt.Printf("  - Fix: %s\n", f.Remediation)
				}
			}
			fmt.Println()
		}
	}

	// Exploit Chains
	fmt.Println()
	fmt.Println("## Exploit Chains")
	if len(report.Chains) == 0 {
		fmt.Println("No exploit chains assembled.")
	} else {
		for _, c := range report.Chains {
			fmt.Printf("### [%s] %s\n", c.Severity, c.Name)
			fmt.Printf("- **Summary:** %s\n", c.Summary)
			for _, s := range c.Steps {
				fmt.Printf("%d. **%s** (%s) — %s\n", s.Order, s.Class, s.Severity, s.FindingTitle)
				fmt.Printf("   - Asset: `%s`\n", s.AffectedAsset)
				if s.Technique != "" {
					fmt.Printf("   - Technique: %s\n", s.Technique)
				}
			}
			fmt.Println()
		}
	}

	fmt.Println("## Exploit Results")
	if len(report.ExploitResults) == 0 {
		fmt.Println("No PoC/exploitation runs performed (enable the exploit module).")
	} else {
		fmt.Println("| Status | Module | Target | Finding | Evidence |")
		fmt.Println("|--------|--------|--------|---------|----------|")
		for _, e := range report.ExploitResults {
			evidence := "—"
			if len(e.Evidence) > 0 {
				evidence = strings.Join(e.Evidence, "; ")
			}
			fmt.Printf("| %s | `%s` | `%s` | %s | %s |\n", e.Status, e.ModuleID, e.Target, e.FindingTitle, evidence)
		}
		fmt.Println()
	}
}
