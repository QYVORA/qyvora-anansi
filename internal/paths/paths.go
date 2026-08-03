// Package paths probes live hosts for exposed sensitive files and endpoints
// such as /.env, /.git/config, /admin, /api-docs, and other common targets.
// It uses a per-host 404 baseline to reduce false positives and follows
// redirect chains to distinguish real endpoints from root-redirects.
package paths

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/QYVORA/qyvora-anansi-cli/internal/assets"
	"github.com/QYVORA/qyvora-anansi-cli/internal/httpclient"
	"github.com/QYVORA/qyvora-anansi-cli/internal/output"
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

type baselineResponse struct {
	statusCode int
	bodyLen    int
}

func getBaseline(client *http.Client, baseURL string) baselineResponse {
	target := strings.TrimRight(baseURL, "/") + fmt.Sprintf("/anansi-404-test-%d", time.Now().UnixNano())
	req, err := http.NewRequestWithContext(context.Background(), "GET", target, nil)
	if err != nil {
		return baselineResponse{statusCode: 404}
	}
	req.Header.Set("User-Agent", output.DefaultUA)

	resp, err := client.Do(req)
	if err != nil {
		return baselineResponse{statusCode: 404}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return baselineResponse{
		statusCode: resp.StatusCode,
		bodyLen:    len(body),
	}
}

func (r pathRule) checkPath(client *http.Client, baseURL string, baseline baselineResponse, stealth bool) *output.Finding {
	target := strings.TrimRight(baseURL, "/") + r.path
	req, err := http.NewRequestWithContext(context.Background(), "GET", target, nil)
	if err != nil {
		return nil
	}

	if stealth {
		req.Header.Set("User-Agent", output.RandomUA())
	} else {
		req.Header.Set("User-Agent", output.DefaultUA)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 || resp.StatusCode == 400 || resp.StatusCode == 410 || resp.StatusCode == 403 {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5000))
	if resp.StatusCode == baseline.statusCode && len(body) == baseline.bodyLen {
		return nil
	}

	severity := r.severity
	title := r.title
	description := fmt.Sprintf("%s returned HTTP %d", r.path, resp.StatusCode)
	evidence := fmt.Sprintf("HTTP %d at %s", resp.StatusCode, target)

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		followClient := &http.Client{
			Timeout:   client.Timeout,
			Transport: client.Transport,
		}
		fReq, fErr := http.NewRequestWithContext(context.Background(), "GET", target, nil)
		if fErr == nil {
			fReq.Header.Set("User-Agent", output.DefaultUA)
			fResp, fRespErr := followClient.Do(fReq)
			if fRespErr == nil {
				defer fResp.Body.Close()
				finalStatus := fResp.StatusCode
				finalURL := fResp.Request.URL.String()

				isRootRedirect := false
				uParsed, pErr := url.Parse(finalURL)
				if pErr == nil {
					pathClean := strings.Trim(uParsed.Path, "/")
					if pathClean == "" || pathClean == "index.html" || pathClean == "index.php" || pathClean == "home" {
						isRootRedirect = true
					}
				}

				if finalStatus == 404 || finalStatus == 400 || finalStatus == 410 || finalStatus == 403 || isRootRedirect {
					severity = output.Info
					title = "[POTENTIAL FALSE POSITIVE] " + r.title
					description = fmt.Sprintf("%s returned HTTP %d but redirects to %s (HTTP %d)", r.path, resp.StatusCode, finalURL, finalStatus)
					evidence = fmt.Sprintf("Redirect: HTTP %d -> %s (HTTP %d)", resp.StatusCode, finalURL, finalStatus)
				} else {
					evidence = fmt.Sprintf("Redirect: HTTP %d -> %s (HTTP %d)", resp.StatusCode, finalURL, finalStatus)
				}
			}
		}
	}

	if severity != output.Info && r.captureBody && (severity == output.Critical || severity == output.High) {
		snippet := strings.ReplaceAll(string(body), "\x00", "")
		snippet = strings.TrimSpace(snippet)
		if len(snippet) > 300 {
			snippet = snippet[:300] + "..."
		}
		if len(snippet) > 0 {
			evidence += "\n  " + snippet
		}
	}

	return &output.Finding{
		Severity:      severity,
		Title:         title,
		AffectedAsset: target,
		Description:   description,
		Evidence:      evidence,
		Remediation:   fmt.Sprintf("Restrict or remove %s from public access.", r.path),
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

	rules := loadRules("wordlists/paths/default.txt")
	if deep {
		rules = append(rules, loadRules("wordlists/paths/deep.txt")...)
	}

	if len(liveHosts) == 0 || len(rules) == 0 {
		return nil
	}

	// Build a per-host baseline cache to avoid re-fetching for every rule.
	baselineCache := make(map[string]baselineResponse, len(liveHosts))
	for _, host := range liveHosts {
		baselineCache[host.URL] = getBaseline(client, host.URL)
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

				f := p.rule.checkPath(client, p.host.URL, baselineCache[p.host.URL], stealth)
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
