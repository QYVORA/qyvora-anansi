// Package paths probes live hosts for exposed sensitive files and endpoints
// such as /.env, /.git/config, /admin, /api-docs, and other common targets.
// It uses a per-host 404 baseline to reduce false positives and follows
// redirect chains to distinguish real endpoints from root-redirects.
//
// In addition to the generic default/deep rule lists it loads two focused
// wordlists: js.txt (common JavaScript bundles, libraries, source maps and
// workers for JS analysis) and sensitive.txt (high-value PHP, config, backup
// and credential files worth downloading for offline analysis). Rules flagged
// captureBody=true have their body captured into the finding evidence so the
// content can be examined further.
package paths

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/QYVORA/qyvora-anansi-cli/internal/assets"
	"github.com/QYVORA/qyvora-anansi-cli/internal/httpclient"
	"github.com/QYVORA/qyvora-anansi-cli/internal/output"
	"github.com/QYVORA/qyvora-anansi-cli/internal/validation"
)

type pathRule struct {
	path        string
	title       string
	severity    string
	captureBody bool
}

func loadRules(filename string) []pathRule {
	lines := assets.LoadData(filename)
	if len(lines) == 0 {
		return nil
	}
	rules := make([]pathRule, 0, len(lines))
	for _, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		capture := len(parts) >= 4 && parts[3] == "true"
		rules = append(rules, pathRule{
			path:        parts[0],
			title:       parts[1],
			severity:    parts[2],
			captureBody: capture,
		})
	}
	return rules
}

// LoadExtensions returns the list of file extensions used for extension-based
// path checks (e.g. probing /admin.php when /admin is found). The list is a
// plain one-per-line set of dot-prefixed extensions from
// wordlists/extensions.txt; entries are returned trimmed and de-duplicated.
func LoadExtensions() []string {
	lines := assets.LoadData("wordlists/extensions.txt")
	seen := make(map[string]struct{}, len(lines))
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		ext := strings.TrimSpace(line)
		if ext == "" || !strings.HasPrefix(ext, ".") {
			continue
		}
		if _, ok := seen[ext]; ok {
			continue
		}
		seen[ext] = struct{}{}
		out = append(out, ext)
	}
	return out
}

// getBaseline is now a simple wrapper around the validation package.
func getBaseline(validator *validation.Validator, baseURL string) *validation.BaselineProfile {
	baseline, _ := validator.GetBaseline(baseURL)
	return baseline
}

func (r pathRule) checkPath(validator *validation.Validator, baseURL string, baseline *validation.BaselineProfile, _ bool) *output.Finding {
	target := strings.TrimRight(baseURL, "/") + r.path

	// Use the validator to properly classify the response
	respInfo, err := validator.Validate(target, baseline)
	if err != nil {
		return nil
	}

	// Determine if this is a high-value target based on severity
	isHighValue := r.severity == output.Critical || r.severity == output.High

	// Check if we should report this finding
	if !validation.ShouldReportFinding(respInfo, isHighValue) {
		return nil
	}

	// Build finding based on validation results
	severity := r.severity
	title := r.title
	var description string
	var evidence string

	// Handle authentication required
	if respInfo.IsAuthRequired {
		severity = output.Medium // Downgrade but still report
		description = fmt.Sprintf("%s requires authentication (original: HTTP %d, final: HTTP %d)",
			r.path, respInfo.OriginalStatus, respInfo.FinalStatus)

		if len(respInfo.RedirectChain) > 0 {
			evidence = "Authentication required - Redirect chain: "
			for i, hop := range respInfo.RedirectChain {
				if i > 0 {
					evidence += " → "
				}
				evidence += fmt.Sprintf("%d to %s", hop.StatusCode, hop.ToURL)
			}
		} else {
			evidence = fmt.Sprintf("HTTP %d at %s", respInfo.FinalStatus, target)
		}
	} else if respInfo.IsAccessDenied {
		// Access denied is interesting - resource exists but forbidden
		severity = output.Medium
		description = fmt.Sprintf("%s exists but access is denied (HTTP 403)", r.path)
		evidence = fmt.Sprintf("HTTP 403 Forbidden at %s", target)
	} else if respInfo.IsRedirect {
		// Clean redirect without auth issues
		description = fmt.Sprintf("%s returned HTTP %d", r.path, respInfo.OriginalStatus)

		evidence = fmt.Sprintf("Original: HTTP %d at %s\n", respInfo.OriginalStatus, target)
		evidence += fmt.Sprintf("Final: HTTP %d at %s", respInfo.FinalStatus, respInfo.FinalURL)

		if len(respInfo.RedirectChain) > 0 {
			evidence += "\nRedirect chain: "
			for i, hop := range respInfo.RedirectChain {
				if i > 0 {
					evidence += " → "
				}
				evidence += fmt.Sprintf("%d", hop.StatusCode)
			}
		}
	} else {
		// Successful direct response
		description = fmt.Sprintf("%s returned HTTP %d", r.path, respInfo.FinalStatus)
		evidence = fmt.Sprintf("HTTP %d at %s", respInfo.FinalStatus, target)
	}

	// Capture body for high-value targets if requested
	if r.captureBody && isHighValue && len(respInfo.Body) > 0 {
		snippet := strings.ReplaceAll(string(respInfo.Body), "\x00", "")
		snippet = strings.TrimSpace(snippet)
		if len(snippet) > 300 {
			snippet = snippet[:300] + "..."
		}
		if len(snippet) > 0 {
			evidence += "\n\nContent preview:\n  " + snippet
		}
	}

	// Add validation notes for transparency
	if len(respInfo.ValidationNotes) > 0 {
		evidence += fmt.Sprintf("\n\nValidation: %s", strings.Join(respInfo.ValidationNotes, "; "))
	}

	return &output.Finding{
		Severity:        severity,
		Title:           title,
		AffectedAsset:   target,
		Description:     description,
		Evidence:        evidence,
		Remediation:     fmt.Sprintf("Restrict or remove %s from public access.", r.path),
		ValidationState: output.ValidationState(validation.ValidationStateClass(respInfo, baseline != nil)),
		FinalURL:        respInfo.FinalURL,
		OriginalStatus:  respInfo.OriginalStatus,
		FinalStatus:     respInfo.FinalStatus,
		RedirectChain:   validation.RedirectSummary(respInfo),
	}
}

// extraPathsFromRobots fetches the host's robots.txt and converts every
// Allow:/Disallow: entry into an extra low-severity probe.  This surfaces
// intentionally-hidden directories (admin panels, backups, staging areas)
// that generic wordlists miss — a cheap depth win (one extra request per host).
func extraPathsFromRobots(client *http.Client, baseURL string) []pathRule {
	target := strings.TrimRight(baseURL, "/") + "/robots.txt"
	req, err := http.NewRequestWithContext(context.Background(), "GET", target, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", output.DefaultUA)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var rules []pathRule
	seen := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		low := strings.ToLower(trimmed)
		var path string
		switch {
		case strings.HasPrefix(low, "disallow:"):
			path = strings.TrimSpace(trimmed[len("Disallow:"):])
		case strings.HasPrefix(low, "allow:"):
			path = strings.TrimSpace(trimmed[len("Allow:"):])
		}
		if path == "" || !strings.HasPrefix(path, "/") || path == "/" {
			continue
		}
		if strings.Contains(path, "*") {
			continue
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		rules = append(rules, pathRule{
			path:     path,
			title:    "Robots.txt Disallowed Path (Reconnaissance)",
			severity: output.Info,
		})
	}
	return rules
}

// Run probes all live hosts for exposed paths and returns any findings.
// A per-host 404 baseline is established first, then each path rule is
// checked against the host in a single flat worker pool — avoiding the
// nested-goroutine pattern that previously caused a race condition.
func Run(out *output.Renderer, liveHosts []output.ProbeResult, deep bool, timeout int, threads int, delayMs int, stealth bool) []output.Finding {
	client := httpclient.NewNoRedirect(timeout)

	// Create validator with proper user agent
	userAgent := output.DefaultUA
	if stealth {
		userAgent = output.RandomUA()
	}
	validator := validation.NewValidator(client, userAgent)

	rules := loadRules("wordlists/paths/default.txt")
	if deep {
		rules = append(rules, loadRules("wordlists/paths/deep.txt")...)
	}
	// Focused wordlists: JavaScript assets for JS analysis and high-value
	// PHP/config/backup files worth downloading. Loaded on every scan so the
	// JavaScript-analysis and file-download behaviour is on by default.
	rules = append(rules, loadRules("wordlists/paths/js.txt")...)
	rules = append(rules, loadRules("wordlists/paths/sensitive.txt")...)

	if len(liveHosts) == 0 || len(rules) == 0 {
		return nil
	}

	// Build a per-host baseline cache to avoid re-fetching for every rule.
	baselineCache := make(map[string]*validation.BaselineProfile, len(liveHosts))
	for _, host := range liveHosts {
		baselineCache[host.URL] = getBaseline(validator, host.URL)
	}

	// Discover per-host extra paths from robots.txt.
	extraByHost := make(map[string][]pathRule, len(liveHosts))
	for _, host := range liveHosts {
		if extras := extraPathsFromRobots(client, host.URL); len(extras) > 0 {
			extraByHost[host.URL] = extras
		}
	}

	// Build flat job list: one job per (host, rule) pair, plus robots-derived rules.
	type pair struct {
		host output.ProbeResult
		rule pathRule
	}

	var pairs []pair
	for _, host := range liveHosts {
		hostRules := rules
		if extras, ok := extraByHost[host.URL]; ok {
			hostRules = make([]pathRule, 0, len(rules)+len(extras))
			hostRules = append(hostRules, rules...)
			hostRules = append(hostRules, extras...)
		}
		for _, rule := range hostRules {
			pairs = append(pairs, pair{host, rule})
		}
	}

	var allFindings []output.Finding
	mu := sync.Mutex{}
	totalJobs := len(pairs)

	// Fixed worker pool: exactly `threads` workers pull (host, rule) pairs from
	// a channel.  Spawning one goroutine per job caused thousands of goroutine
	// creations and lock-contended progress updates on wordlists of 8k+ rules;
	// the pool keeps concurrency stable and progress updates atomic.
	workers := threads
	if workers > totalJobs {
		workers = totalJobs
	}
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan pair)
	var wg sync.WaitGroup
	var completed atomic.Int64

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				delay := output.JitterDelay(delayMs, stealth)
				if delay > 0 {
					time.Sleep(delay)
				}

				f := p.rule.checkPath(validator, p.host.URL, baselineCache[p.host.URL], stealth)
				if f != nil {
					mu.Lock()
					allFindings = append(allFindings, *f)
					mu.Unlock()
				} else {
					out.Verbose(fmt.Sprintf("Path not found: %s%s", p.host.URL, p.rule.path))
				}

				c := completed.Add(1)
				if c%10 == 0 || c == int64(totalJobs) {
					out.Progress(int(c), totalJobs, "Probing Paths")
				}
			}
		}()
	}

	for _, p := range pairs {
		jobs <- p
	}
	close(jobs)
	wg.Wait()

	return allFindings
}
