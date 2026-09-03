// Package probe implements HTTP/HTTPS connectivity testing against live hosts.
// It captures response metadata (status codes, headers, page titles, redirect
// chains) and identifies web technologies through header and body fingerprinting.
package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/QYVORA/qyvora-anansi/internal/assets"
	"github.com/QYVORA/qyvora-anansi/internal/httpclient"
	"github.com/QYVORA/qyvora-anansi/internal/output"
)

var (
	techHeadersOnce sync.Once
	techHeaders     []string
)

func loadTechHeaders() {
	techHeadersOnce.Do(func() {
		techHeaders = assets.LoadData("wordlists/probe/tech_headers.txt")
	})
}

// newClient creates a shared, connection-pooled HTTP client.  InsecureSkipVerify
// allows probing hosts with invalid or self-signed certificates.  Up to three
// redirects are followed.
func newClient(timeoutSec int) *http.Client {
	return httpclient.NewFollowRedirects(timeoutSec)
}

// probeURL attempts to fetch a single URL and returns metadata about the
// response: status code, headers, page title, server info, response time,
// and detected technologies.  Returns nil on transport error.
func probeURL(client *http.Client, url string, stealth bool) *output.ProbeResult {
	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return nil
	}

	if stealth {
		req.Header.Set("User-Agent", output.RandomUA())
	} else {
		req.Header.Set("User-Agent", output.DefaultUA)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	elapsed := time.Since(start).Milliseconds()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	title := ""
	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		if idx := strings.Index(strings.ToLower(string(body)), "<title"); idx != -1 {
			sub := string(body)[idx:]
			startIdx := strings.Index(sub, ">") + 1
			endIdx := strings.Index(strings.ToLower(sub), "</title>")
			if startIdx > 0 && endIdx > startIdx && endIdx-startIdx < 200 {
				title = strings.TrimSpace(sub[startIdx:endIdx])
			}
		}
	}

	loadTechHeaders()
	tech := map[string]string{}
	for _, h := range techHeaders {
		if v := resp.Header.Get(h); v != "" {
			tech[h] = v
		}
	}

	detectedTechs := detectTech(resp.Header, body)

	return &output.ProbeResult{
		URL:            url,
		FinalURL:       resp.Request.URL.String(),
		StatusCode:     resp.StatusCode,
		Server:         resp.Header.Get("Server"),
		TechHeaders:    tech,
		Technologies:   detectedTechs,
		Title:          title,
		ResponseTimeMs: elapsed,
		IsAlive:        true,
	}
}

// detectTech parses HTTP response headers and body for known web
// technology fingerprints.
func detectTech(headers http.Header, body []byte) []string {
	var techs []string
	bodyStr := strings.ToLower(string(body))

	poweredBy := strings.ToLower(headers.Get("X-Powered-By"))
	if strings.Contains(poweredBy, "php") {
		techs = append(techs, "PHP")
	}
	if strings.Contains(poweredBy, "asp.net") {
		techs = append(techs, "ASP.NET")
	}
	if headers.Get("X-AspNet-Version") != "" {
		techs = append(techs, "ASP.NET")
	}

	server := strings.ToLower(headers.Get("Server"))
	switch {
	case strings.Contains(server, "cloudflare"):
		techs = append(techs, "Cloudflare")
	case strings.Contains(server, "nginx"):
		techs = append(techs, "Nginx")
	case strings.Contains(server, "apache"):
		techs = append(techs, "Apache")
	}

	switch {
	case strings.Contains(bodyStr, "wordpress") || strings.Contains(bodyStr, "/wp-content/"):
		techs = append(techs, "WordPress")
	case strings.Contains(bodyStr, "_next/static") || strings.Contains(bodyStr, "__next"):
		techs = append(techs, "Next.js")
	case strings.Contains(bodyStr, "react-dom") || strings.Contains(bodyStr, "react.production") || strings.Contains(bodyStr, "data-reactroot"):
		techs = append(techs, "React")
	case strings.Contains(bodyStr, "drupal") || strings.Contains(bodyStr, "sites/default/files"):
		techs = append(techs, "Drupal")
	case strings.Contains(bodyStr, "joomla"):
		techs = append(techs, "Joomla")
	case strings.Contains(bodyStr, "<app-root>"):
		techs = append(techs, "Angular")
	}

	return techs
}

// probeHost tests multiple port/scheme combinations for a single FQDN and
// returns results for all responsive ports.
func probeHost(client *http.Client, fqdn string, ports []string, delayMs int, stealth bool) []*output.ProbeResult {
	var results []*output.ProbeResult
	for _, port := range ports {
		j := output.JitterDelay(delayMs, stealth)
		if j > 0 {
			time.Sleep(j)
		}

		var schemes []string
		if port == "443" || port == "8443" {
			schemes = []string{"https", "http"}
		} else {
			schemes = []string{"http", "https"}
		}

		for _, scheme := range schemes {
			url := fmt.Sprintf("%s://%s:%s", scheme, fqdn, port)
			if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
				url = fmt.Sprintf("%s://%s", scheme, fqdn)
			}
			if r := probeURL(client, url, stealth); r != nil {
				r.FQDN = fqdn
				results = append(results, r)
				break
			}
		}
	}
	if len(results) == 0 {
		return []*output.ProbeResult{{FQDN: fqdn, IsAlive: false}}
	}
	return results
}

// Run probes all hosts concurrently with a semaphore to limit parallelism.
func Run(out *output.Renderer, hosts []string, timeout int, threads int, ports []string, delayMs int, stealth bool) ([]output.ProbeResult, error) {
	client := newClient(timeout)
	results := make([]output.ProbeResult, 0, len(hosts))
	mu := sync.Mutex{}
	var wg sync.WaitGroup
	var completed atomic.Int64

	workers := threads
	if workers > len(hosts) {
		workers = len(hosts)
	}
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan string)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				rs := probeHost(client, h, ports, delayMs, stealth)
				mu.Lock()
				for _, r := range rs {
					results = append(results, *r)
				}
				c := completed.Add(1)
				if c%5 == 0 || c == int64(len(hosts)) {
					out.Progress(int(c), len(hosts), "Probing")
				}
				mu.Unlock()
			}
		}()
	}

	for _, host := range hosts {
		jobs <- host
	}
	close(jobs)
	wg.Wait()
	return results, nil
}

// LiveOnly filters a ProbeResult slice to return only hosts that
// responded successfully.
func LiveOnly(results []output.ProbeResult) []output.ProbeResult {
	var live []output.ProbeResult
	for _, r := range results {
		if r.IsAlive {
			live = append(live, r)
		}
	}
	return live
}
