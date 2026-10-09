package osint

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/QYVORA/qyvora-anansi/internal/httpclient"
	"github.com/QYVORA/qyvora-anansi/internal/output"
)

func Run(ctx context.Context, out *output.Renderer, probeResults []output.ProbeResult, target string, timeout int, threads int, _ int, stealth bool) []output.OSINTResult {
	var results []output.OSINTResult
	client := httpclient.NewFollowRedirects(timeout)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	var cancelled atomic.Bool

	collect := func(r output.OSINTResult) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	}

	// 1. WHOIS lookup
	wg.Add(1)
	sem <- struct{}{}
	go func() {
		defer wg.Done()
		defer func() { <-sem }()
		if cancelled.Load() || ctx.Err() != nil {
			return
		}
		_, whoisResults := whoisLookup(target)
		for _, r := range whoisResults {
			collect(r)
		}
	}()

	// 2. Scrape live hosts for emails, phones, employees
	for _, page := range extractRelevantPages(probeResults) {
		if cancelled.Load() || ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(url string) {
			defer wg.Done()
			defer func() { <-sem }()
			if cancelled.Load() || ctx.Err() != nil {
				cancelled.Store(true)
				return
			}

			body, err := fetchPage(client, url, stealth)
			if err != nil {
				out.Verbose(fmt.Sprintf("  skip %s: %v", url, err))
				return
			}

			for _, email := range extractEmails(body) {
				collect(output.OSINTResult{
					Category: "email",
					Value:    email,
					Source:   url,
					Context:  "page",
				})
			}

			for _, phone := range extractPhones(body) {
				collect(output.OSINTResult{
					Category: "phone",
					Value:    phone,
					Source:   url,
					Context:  "page",
				})
			}

			if isPeoplePage(url) {
				for _, name := range extractEmployeeNames(body) {
					collect(output.OSINTResult{
						Category: "employee",
						Value:    name,
						Source:   url,
						Context:  "team page",
					})
				}
			}
		}(page)
	}

	wg.Wait()
	return results
}

func extractRelevantPages(probeResults []output.ProbeResult) []string {
	seen := map[string]bool{}
	urls := make([]string, 0, len(probeResults))
	for _, p := range probeResults {
		if !p.IsAlive || p.URL == "" || seen[p.URL] {
			continue
		}
		seen[p.URL] = true
		urls = append(urls, p.URL)
	}
	return urls
}

func isPeoplePage(url string) bool {
	lower := strings.ToLower(url)
	for _, path := range []string{"/about", "/team", "/contact", "/people", "/leadership", "/staff", "/employees", "/management", "/our-team", "/about-us", "/who-we-are"} {
		if strings.Contains(lower, path) {
			return true
		}
	}
	return false
}
