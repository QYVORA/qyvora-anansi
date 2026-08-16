// Package discovery implements subdomain enumeration through two techniques:
//  1. Certificate Transparency logs via crt.sh API
//  2. DNS brute-force using built-in wordlists
//
// All discovered candidates are resolved concurrently; results include live
// IP addresses as well as dead CNAME records that may indicate a subdomain
// takeover vulnerability.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/QYVORA/qyvora-anansi-cli/internal/assets"
	"github.com/QYVORA/qyvora-anansi-cli/internal/dnscache"
	"github.com/QYVORA/qyvora-anansi-cli/internal/httpclient"
	"github.com/QYVORA/qyvora-anansi-cli/internal/output"
)

// dnsResolver is the pure-Go resolver.  It bypasses cgo-backed system lookups
// and keeps DNS resolution fully concurrent inside goroutines.
var dnsResolver = &net.Resolver{
	PreferGo: true,
}

// resolver wraps dnsResolver with a TTL cache.  Recursive and mutation phases
// frequently re-resolve the same subdomains, so caching avoids redundant
// resolver round-trips.
var resolver = dnscache.New(dnsResolver, 60*time.Second, 20000)

type crtEntry struct {
	NameValue string `json:"name_value"`
}

// resolveJob is a single subdomain to resolve, carrying its source label
// so the caller knows whether it came from crt.sh, a wordlist, etc.
type resolveJob struct {
	fqdn   string
	source string
}

// fetchCrtSh queries the crt.sh Certificate Transparency log for all
// certificates matching "%.target.com" and returns deduplicated DNS names.
// A doubled timeout is used because crt.sh can be slow.
func fetchCrtSh(target string, timeout int) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout*2)*time.Second)
	defer cancel()
	client := httpclient.NewFollowRedirects(timeout)
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var entries []crtEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("json decode error: %w", err)
	}

	seen := map[string]struct{}{}
	var results []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			clean := strings.ToLower(strings.TrimSpace(name))
			clean = strings.TrimPrefix(clean, "*.")
			if strings.HasSuffix(clean, "."+target) || clean == target {
				if _, exists := seen[clean]; !exists {
					seen[clean] = struct{}{}
					results = append(results, clean)
				}
			}
		}
	}
	return results, nil
}

// resolveHost attempts to resolve a FQDN to IP addresses.  When the host
// does not resolve it checks for a CNAME record; if the CNAME itself does
// not resolve the host is flagged as a "dead CNAME" (potential takeover).
func resolveHost(ctx context.Context, fqdn string) ([]string, []string) {
	ips, err := resolver.LookupHost(ctx, fqdn)
	if err != nil {
		cname, cerr := resolver.LookupCNAME(ctx, fqdn)
		if cerr == nil && cname != fqdn+"." {
			return nil, []string{strings.TrimSuffix(cname, ".")}
		}
		return nil, nil
	}

	var publicIPs []string
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed != nil && !parsed.IsPrivate() && !parsed.IsLoopback() {
			publicIPs = append(publicIPs, ip)
		}
	}
	return publicIPs, nil
}

// detectWildcard probes a random non-existent subdomain to check whether
// the target domain uses a wildcard DNS record.
func detectWildcard(ctx context.Context, target string) []string {
	randomSub := fmt.Sprintf("anansi-wildcard-test-%d.%s", time.Now().UnixNano(), target)
	ips, _ := resolver.LookupHost(ctx, randomSub)
	return ips
}

// isWildcardResult returns true when every IP in ips belongs to the
// wildcard IP set, indicating a wildcard false-positive.
func isWildcardResult(ips []string, wildcardMap map[string]struct{}) bool {
	if len(wildcardMap) == 0 || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if _, ok := wildcardMap[ip]; !ok {
			return false
		}
	}
	return true
}

// resolveMany resolves a slice of jobs concurrently with the given
// concurrency, timeout, and optional inter-request delay.  Wildcard
// filtering is applied to wordlist-sourced results when wildcardMap is
// non-empty.  Results are appended to the provided slice (thread-safe).
func resolveMany(jobs []resolveJob, results *[]output.SubdomainResult, threads, timeout, delayMs int, wildcardMap map[string]struct{}, stealth bool, label string, out *output.Renderer) {
	if len(jobs) == 0 {
		return
	}

	var wg sync.WaitGroup
	mu := sync.Mutex{}
	var completed atomic.Int64

	workers := threads
	if workers > len(jobs) {
		workers = len(jobs)
	}
	if workers < 1 {
		workers = 1
	}

	jobsCh := make(chan resolveJob)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobsCh {
				delay := output.JitterDelay(delayMs, stealth)
				if delay > 0 {
					time.Sleep(delay)
				}

				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
				ips, deadCNAMEs := resolveHost(ctx, j.fqdn)
				cancel()

				if len(ips) > 0 && isWildcardResult(ips, wildcardMap) && j.source == output.SourceWordlist {
					ips = nil
				}

				result := output.SubdomainResult{
					FQDN:       j.fqdn,
					Source:     j.source,
					IPs:        ips,
					DeadCNAMEs: deadCNAMEs,
					Resolved:   len(ips) > 0,
				}

				mu.Lock()
				*results = append(*results, result)
				c := completed.Add(1)
				if c%10 == 0 || c == int64(len(jobs)) {
					out.Progress(int(c), len(jobs), label)
				}
				mu.Unlock()
			}
		}()
	}

	for _, j := range jobs {
		jobsCh <- j
	}
	close(jobsCh)
	wg.Wait()
}

// buildCandidateList combines crt.sh results with wordlist entries into a
// deduplicated job list.  The apex domain is always included.
func buildCandidateList(crtDomains []string, wordlist []string, target string) []resolveJob {
	seen := map[string]string{}
	for _, d := range crtDomains {
		seen[d] = output.SourceCrtSh
	}
	if _, exists := seen[target]; !exists {
		seen[target] = output.SourceWordlist
	}
	for _, prefix := range wordlist {
		fqdn := prefix + "." + target
		if _, exists := seen[fqdn]; !exists {
			seen[fqdn] = output.SourceWordlist
		}
	}

	jobs := make([]resolveJob, 0, len(seen))
	for fqdn, src := range seen {
		jobs = append(jobs, resolveJob{fqdn, src})
	}
	return jobs
}

// Run executes the full subdomain discovery pipeline:
//  1. Detect DNS wildcard
//  2. Fetch subdomains from crt.sh (skipped in stealth mode)
//  3. Generate candidates from wordlist
//  4. Resolve all candidates concurrently
//  5. Optionally run recursive and mutation brute-force
func Run(out *output.Renderer, target string, deep bool, timeout int, customWordlist string, threads int, recursive bool, mutate bool, delayMs int, stealth bool) ([]output.SubdomainResult, error) {
	// -- Wildcard detection ------------------------------------------------
	out.Info("Detecting DNS wildcard...")
	ctxWildcard, cancelWildcard := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	wildcardIPs := detectWildcard(ctxWildcard, target)
	cancelWildcard()

	wildcardMap := make(map[string]struct{})
	for _, ip := range wildcardIPs {
		wildcardMap[ip] = struct{}{}
		out.Info(fmt.Sprintf("Wildcard detected resolving to %s", ip))
	}

	// -- crt.sh (skipped in stealth mode to avoid CT logging) --------------
	var crtDomains []string
	if stealth {
		out.Info("Stealth mode: skipping crt.sh query")
	} else {
		out.Info("Querying crt.sh (Certificate Transparency)...")
		crtDomains, _ = fetchCrtSh(target, timeout)
		out.Info(fmt.Sprintf("crt.sh found %d potential subdomains", len(crtDomains)))
	}

	// -- Load wordlist -----------------------------------------------------
	wordlist := assets.LoadWordlist(customWordlist, deep)

	// -- Build candidate list ----------------------------------------------
	jobs := buildCandidateList(crtDomains, wordlist, target)
	out.Info(fmt.Sprintf("Resolving %d candidates with %d threads...", len(jobs), threads))

	// -- Resolve all candidates concurrently -------------------------------
	results := make([]output.SubdomainResult, 0, len(jobs))
	resolveMany(jobs, &results, threads, timeout, delayMs, wildcardMap, stealth, "Resolving", out)

	// -- Recursive brute-force ---------------------------------------------
	if recursive {
		runRecursive(&results, wordlist, target, threads, timeout, delayMs, wildcardMap, stealth, out)
	}

	// -- Mutation brute-force ----------------------------------------------
	if mutate {
		runMutation(&results, target, threads, timeout, delayMs, wildcardMap, stealth, out)
	}

	return results, nil
}

// runRecursive resolves every wordlist prefix under each already-resolved
// subdomain to discover deeper nested subdomains.
func runRecursive(results *[]output.SubdomainResult, wordlist []string, target string, threads, timeout, delayMs int, wildcardMap map[string]struct{}, stealth bool, out *output.Renderer) {
	var resolvedSubs []string
	for _, r := range *results {
		if r.Resolved && r.FQDN != target {
			resolvedSubs = append(resolvedSubs, r.FQDN)
		}
	}
	if len(resolvedSubs) == 0 {
		return
	}

	out.Info(fmt.Sprintf("Running recursive brute-force on %d resolved subdomains...", len(resolvedSubs)))

	seen := map[string]struct{}{}
	for _, r := range *results {
		seen[r.FQDN] = struct{}{}
	}

	var recJobs []resolveJob
	for _, sub := range resolvedSubs {
		for _, prefix := range wordlist {
			fqdn := prefix + "." + sub
			if _, exists := seen[fqdn]; !exists {
				seen[fqdn] = struct{}{}
				recJobs = append(recJobs, resolveJob{fqdn, output.SourceWordlist})
			}
		}
	}

	resolveMany(recJobs, results, threads, timeout, delayMs, wildcardMap, stealth, "Recursive resolving", out)
}

// runMutation applies prefix-level mutations (hyphenation, number
// increments, cross-combination) to already-resolved subdomains and
// resolves the resulting candidates.
func runMutation(results *[]output.SubdomainResult, target string, threads, timeout, delayMs int, wildcardMap map[string]struct{}, stealth bool, out *output.Renderer) {
	var resolvedSubs []string
	for _, r := range *results {
		if r.Resolved && r.FQDN != target {
			resolvedSubs = append(resolvedSubs, r.FQDN)
		}
	}

	mutatedCandidates := MutateSubdomains(resolvedSubs, target)
	if len(mutatedCandidates) == 0 {
		return
	}

	out.Info(fmt.Sprintf("Running subdomain mutation brute-force on %d candidates...", len(mutatedCandidates)))

	seen := map[string]struct{}{}
	for _, r := range *results {
		seen[r.FQDN] = struct{}{}
	}

	var mutJobs []resolveJob
	for _, candidate := range mutatedCandidates {
		if _, exists := seen[candidate]; !exists {
			seen[candidate] = struct{}{}
			mutJobs = append(mutJobs, resolveJob{candidate, output.SourceMutation})
		}
	}

	resolveMany(mutJobs, results, threads, timeout, delayMs, wildcardMap, stealth, "Mutation resolving", out)
}

// MutateSubdomains generates target-specific subdomain mutations from
// resolved prefixes: hyphenated common words, number increments, and
// cross-combinations of discovered prefixes.
func MutateSubdomains(resolved []string, target string) []string {
	prefixes := make([]string, 0)
	for _, fqdn := range resolved {
		prefix := strings.TrimSuffix(fqdn, "."+target)
		if prefix != target && prefix != "" {
			prefixes = append(prefixes, prefix)
		}
	}

	if len(prefixes) == 0 {
		return nil
	}

	seen := map[string]struct{}{}
	commonWords := []string{"admin", "staging", "test", "prod", "internal", "dev", "api", "static", "corp"}

	for _, p := range prefixes {
		for _, w := range commonWords {
			if w != p {
				seen[p+"-"+w] = struct{}{}
				seen[w+"-"+p] = struct{}{}
			}
		}
		lastChar := p[len(p)-1]
		if lastChar >= '0' && lastChar <= '9' {
			base := p[:len(p)-1]
			for _, n := range []string{"1", "2", "3", "4", "5"} {
				seen[base+n] = struct{}{}
			}
		}
	}

	if len(prefixes) > 1 {
		maxCombos := 100
		count := 0
		for i := 0; i < len(prefixes) && count < maxCombos; i++ {
			for j := 0; j < len(prefixes) && count < maxCombos; j++ {
				if i != j {
					seen[prefixes[i]+"-"+prefixes[j]] = struct{}{}
					count++
				}
			}
		}
	}

	mutated := make([]string, 0, len(seen))
	for m := range seen {
		mutated = append(mutated, m+"."+target)
	}

	return mutated
}

// LiveHosts filters a slice of SubdomainResult to return only the FQDNs
// that resolved successfully.
func LiveHosts(subdomains []output.SubdomainResult) []string {
	var live []string
	for _, s := range subdomains {
		if s.Resolved {
			live = append(live, s.FQDN)
		}
	}
	return live
}
