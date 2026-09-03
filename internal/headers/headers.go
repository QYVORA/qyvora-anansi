// Package headers audits HTTP security response headers and CORS configuration.
// It checks for the presence of HSTS, CSP, X-Frame-Options, X-Content-Type-
// Options, Referrer-Policy, and Permissions-Policy, and tests for CORS
// misconfigurations including wildcard origins and origin reflection.
package headers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/QYVORA/qyvora-anansi/internal/assets"
	"github.com/QYVORA/qyvora-anansi/internal/httpclient"
	"github.com/QYVORA/qyvora-anansi/internal/output"
)

type headerRule struct {
	header      string
	title       string
	severity    string
	description string
	remediation string
}

var (
	loadRulesOnce   sync.Once
	securityHeaders []string
	headerRules     []headerRule
)

func loadHeaderRules() {
	loadRulesOnce.Do(func() {
		lines := assets.LoadData("wordlists/headers/rules.txt")
		for _, line := range lines {
			parts := strings.Split(line, "|")
			if len(parts) == 5 {
				rule := headerRule{
					header:      parts[0],
					title:       parts[1],
					severity:    parts[2],
					description: parts[3],
					remediation: parts[4],
				}
				headerRules = append(headerRules, rule)
				securityHeaders = append(securityHeaders, rule.header)
			}
		}
	})
}

// auditURL fetches the given URL and inspects its response headers for
// security-related headers and CORS misconfigurations.
func auditURL(client *http.Client, url string, stealth bool) *output.HeaderResult {
	loadHeaderRules()

	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return &output.HeaderResult{
			URL:     url,
			Success: false,
			Error:   err.Error(),
		}
	}

	if stealth {
		req.Header.Set("User-Agent", output.RandomUA())
	} else {
		req.Header.Set("User-Agent", output.DefaultUA)
	}
	req.Header.Set("Origin", "https://evil-attacker.com")

	resp, err := client.Do(req)
	if err != nil {
		return &output.HeaderResult{
			URL:     url,
			Success: false,
			Error:   err.Error(),
		}
	}
	// Drain and close body to allow connection reuse; limit read to 4K
	_, _ = io.CopyN(io.Discard, resp.Body, 4096)
	_ = resp.Body.Close()

	// Do not audit error responses: a 5xx indicates the server is unhealthy.
	// Missing headers or reflecting CORS on error pages are not actionable.
	if resp.StatusCode >= 500 {
		return &output.HeaderResult{
			URL:     url,
			Headers: map[string]string{},
			Success: true,
		}
	}

	hmap := map[string]string{}
	for _, h := range securityHeaders {
		hmap[h] = resp.Header.Get(h)
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	result := &output.HeaderResult{
		URL:     url,
		Headers: hmap,
		CORS:    acao,
		Success: true,
	}

	for _, rule := range headerRules {
		if hmap[rule.header] == "" {
			result.Findings = append(result.Findings, output.Finding{
				Severity:      rule.severity,
				Confidence:    output.ConfLow,
				Title:         rule.title,
				AffectedAsset: url,
				Description:   rule.description,
				Evidence:      "Header \"" + rule.header + "\" absent from response",
				Remediation:   rule.remediation,
			})
		}
	}

	if acao == "*" {
		result.Findings = append(result.Findings, output.Finding{
			Severity:      output.Medium,
			Confidence:    output.ConfMedium,
			Title:         "CORS Wildcard Origin",
			AffectedAsset: url,
			Description:   "Server allows requests from any origin.",
			Evidence:      "Access-Control-Allow-Origin: *",
			Remediation:   "Restrict CORS to specific trusted origins.",
		})
	} else if strings.Contains(acao, "evil-attacker.com") {
		sev := output.High
		conf := output.ConfHigh
		title := "CORS Origin Reflection"
		desc := "Server reflects arbitrary Origin header."
		if strings.EqualFold(acac, "true") {
			sev = output.Critical
			conf = output.Confirmed
			title = "CORS Origin Reflection with Credentials"
			desc = "Server reflects arbitrary origin AND allows credentials — full CORS exploit chain possible."
		}
		result.Findings = append(result.Findings, output.Finding{
			Severity:      sev,
			Confidence:    conf,
			Title:         title,
			AffectedAsset: url,
			Description:   desc,
			Evidence:      "ACAO: " + acao + " | ACAC: " + acac,
			Remediation:   "Validate Origin against a strict allowlist. Never combine reflection with credentials.",
		})
	}

	return result
}

// Run audits security headers for all live probe results concurrently.
func Run(_ []output.ProbeResult, liveHosts []output.ProbeResult, timeout int, threads int, delayMs int, stealth bool) []output.HeaderResult {
	results := make([]output.HeaderResult, 0, len(liveHosts))
	client := httpclient.NewFollowRedirects(timeout)
	var mu sync.Mutex
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, p := range liveHosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(pr output.ProbeResult) {
			defer wg.Done()
			defer func() { <-sem }()
			delay := output.JitterDelay(delayMs, stealth)
			if delay > 0 {
				time.Sleep(delay)
			}
			r := auditURL(client, pr.URL, stealth)
			if r != nil {
				mu.Lock()
				results = append(results, *r)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return results
}
