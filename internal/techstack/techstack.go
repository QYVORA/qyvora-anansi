// Package techstack implements the deep application-stack audit.  When a live
// host is fingerprinted as WordPress, Drupal, Joomla, or another platform, the
// scanner descends that stack: it detects the exact version, enumerates
// WordPress plugins/themes from the homepage body, probes stack-specific
// endpoints (login pages, XML-RPC, REST user enumeration, config backups,
// directory listings), and matches the detected versions against a curated
// table of known-vulnerable versions (CVE-backed).
//
// Speed design: the homepage body fetched here is used for fingerprinting,
// version extraction (generator meta tags / static asset query strings), and
// plugin discovery — minimising redundant requests.  All requests reuse the
// shared connection pool from internal/httpclient.
package techstack

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/QYVORA/qyvora-anansi/internal/assets"
	"github.com/QYVORA/qyvora-anansi/internal/httpclient"
	"github.com/QYVORA/qyvora-anansi/internal/output"
	"github.com/QYVORA/qyvora-anansi/internal/validation"
)

// fingerprint maps a case-insensitive homepage-body needle to a stack name.
type fingerprint struct {
	name   string
	needle string
}

// vulnRule describes a known-vulnerable version range for a stack component.
type vulnRule struct {
	cms         string
	target      string // "core" or "plugin:<slug>"
	title       string
	severity    string
	minVer      string
	maxVer      string
	description string
	remediation string
}

// pathRule is a stack-specific path probe.  A rule is confirmed when any of
// bodyMatch / locationMatch matches, or (when neither is set) when the status
// code is not an obvious not-found/denied response.
type pathRule struct {
	path          string
	title         string
	severity      string
	bodyMatch     string
	locationMatch string
}

// pluginInfo is a WordPress plugin with its detected stable version.
type pluginInfo struct {
	slug    string
	version string
}

var (
	loadOnce        sync.Once
	fingerprints    []fingerprint
	vulnRules       []vulnRule
	genericRules    []pathRule
	stackRules      map[string][]pathRule
	curatedWPPlugin = []string{
		"elementor", "elementor-pro", "wp-file-manager", "duplicator",
		"contact-form-7", "revslider", "woocommerce",
	}
)

var (
	wpEmojiVer   = regexp.MustCompile(`wp-emoji-release\.min\.js\?ver=([0-9a-zA-Z.\-]+)`)
	wpGenVer     = regexp.MustCompile(`generator"?\s+content="WordPress\s+([0-9.]+)`)
	wpOrgVer     = regexp.MustCompile(`wordpress\.org/feed/?\?v=([0-9.]+)`)
	wpCoreVer    = regexp.MustCompile(`(?i)generator.*?wordpress\.org/\?v=([0-9.]+)`)
	drupalChange = regexp.MustCompile(`Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	joomlaXMLVer = regexp.MustCompile(`<version>([0-9.]+)</version>`)
	joomlaReadme = regexp.MustCompile(`Joomla!\s+([0-9.]+)`)
	magentoVer   = regexp.MustCompile(`Magento/([0-9][0-9a-zA-Z.\-]*)`)
	ghostGenVer  = regexp.MustCompile(`(?i)generator"?\s+content=["']Ghost\s+([0-9.]+)`)
	mediawikiVer = regexp.MustCompile(`MediaWiki\s+([0-9]+\.[0-9.]+)`)
	moodleVer    = regexp.MustCompile(`Moodle\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	pluginStable = regexp.MustCompile(`(?i)Stable tag:\s*([0-9][0-9a-zA-Z.\-]*)`)
	pluginRe     = regexp.MustCompile(`wp-content/plugins/([a-zA-Z0-9\-_.]+)/`)
	themeRe      = regexp.MustCompile(`wp-content/themes/([a-zA-Z0-9\-_.]+)/`)
	drupalModule = regexp.MustCompile(`sites/(?:all|default)/modules/([a-zA-Z0-9\-_.]+)/`)
	joomlaCom    = regexp.MustCompile(`/(?:administrator/)?components/com_([a-zA-Z0-9\-_.]+)/`)
	mediawikiExt = regexp.MustCompile(`/extensions/([a-zA-Z0-9\-_.]+)/`)
	cleanVersion = regexp.MustCompile(`^\d+(\.\d+){0,4}$`)
)

func load() {
	loadOnce.Do(func() {
		for _, line := range assets.LoadData("wordlists/tech/fingerprints.txt") {
			parts := strings.SplitN(line, "|", 2)
			if len(parts) == 2 && parts[1] != "" {
				fingerprints = append(fingerprints, fingerprint{name: parts[0], needle: strings.ToLower(parts[1])})
			}
		}

		for _, line := range assets.LoadData("wordlists/tech/vulns.txt") {
			parts := strings.Split(line, "|")
			if len(parts) != 8 {
				continue
			}
			vulnRules = append(vulnRules, vulnRule{
				cms:         parts[0],
				target:      parts[1],
				title:       parts[2],
				severity:    parts[3],
				minVer:      parts[4],
				maxVer:      parts[5],
				description: parts[6],
				remediation: parts[7],
			})
		}

		stackRules = map[string][]pathRule{}
		for _, stack := range []string{"wordpress", "drupal", "joomla", "magento", "ghost", "moodle", "mediawiki", "laravel"} {
			stackRules[stack] = loadPathRules("wordlists/tech/" + stack + ".txt")
		}
		genericRules = loadPathRules("wordlists/tech/generic.txt")
	})
}

func loadPathRules(filename string) []pathRule {
	var rules []pathRule
	for _, line := range assets.LoadData(filename) {
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		r := pathRule{path: parts[0], title: parts[1], severity: parts[2]}
		if len(parts) > 3 {
			r.bodyMatch = parts[3]
		}
		if len(parts) > 4 {
			r.locationMatch = parts[4]
		}
		rules = append(rules, r)
	}
	return rules
}

// Run audits every live host for its detected application stack.  Hosts are
// processed concurrently, bounded by the thread semaphore.  The homepage is
// fetched once and reused for fingerprinting, version extraction, and plugin
// discovery to minimise redundant requests.
func Run(out *output.Renderer, liveHosts []output.ProbeResult, timeout int, threads int, delayMs int, stealth bool) []output.TechResult {
	load()

	hosts := dedupeHosts(liveHosts)
	if len(hosts) == 0 {
		return nil
	}

	follow := httpclient.NewFollowRedirects(timeout)
	noRedirect := httpclient.NewNoRedirect(timeout)

	results := make([]output.TechResult, 0, len(hosts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	var completed atomic.Int64

	out.Info(fmt.Sprintf("Deep-stack audit on %d live hosts...", len(hosts)))

	workers := threads
	if workers > len(hosts) {
		workers = len(hosts)
	}
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan output.ProbeResult)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				delay := output.JitterDelay(delayMs, stealth)
				if delay > 0 {
					time.Sleep(delay)
				}

				tr := auditHost(follow, noRedirect, host, stealth)
				if tr != nil {
					mu.Lock()
					results = append(results, *tr)
					mu.Unlock()
				}

				c := completed.Add(1)
				if c%5 == 0 || c == int64(len(hosts)) {
					out.Progress(int(c), len(hosts), "Tech-stack audit")
				}
			}
		}()
	}

	for _, h := range hosts {
		jobs <- h
	}
	close(jobs)
	wg.Wait()

	return results
}

// dedupeHosts keeps one URL per FQDN, preferring HTTPS.
func dedupeHosts(liveHosts []output.ProbeResult) []output.ProbeResult {
	best := map[string]output.ProbeResult{}
	for _, p := range liveHosts {
		if !p.IsAlive {
			continue
		}
		if prev, ok := best[p.FQDN]; ok {
			if strings.HasPrefix(prev.URL, "https://") {
				continue
			}
		}
		best[p.FQDN] = p
	}
	hosts := make([]output.ProbeResult, 0, len(best))
	for _, p := range best {
		hosts = append(hosts, p)
	}
	return hosts
}

// auditHost performs the full deep audit of one host and returns nil when
// nothing interesting was found (no stack, no findings).
func auditHost(follow, noRedirect *http.Client, host output.ProbeResult, stealth bool) *output.TechResult {
	base := strings.TrimRight(host.URL, "/")
	if base == "" {
		return nil
	}

	body, status := fetch(follow, base, stealth)
	if status == 0 {
		return nil
	}

	// Create a validator for proper soft-404 and baseline detection.
	ua := output.DefaultUA
	if stealth {
		ua = output.RandomUA()
	}
	validator := validation.NewValidator(noRedirect, ua)
	baseline, _ := validator.GetBaseline(base)

	stacks := detectStacks(body)
	var findings []output.Finding
	var components []string

	primary := ""
	version := ""
	detectedBy := ""

	for _, stack := range stacks {
		if primary == "" {
			primary = stack
		}
		ver, src := detectVersion(follow, base, stack, body, stealth)
		if version == "" && ver != "" {
			version, detectedBy = ver, src
		}

		findings = append(findings, matchVulns(stack, "core", ver, base)...)

		if stack == "WordPress" {
			for _, theme := range themeRe.FindAllStringSubmatch(body, -1) {
				components = appendUnique(components, "theme:"+strings.ToLower(theme[1]))
			}
			for _, p := range discoverPlugins(follow, base, body, stealth) {
				if p.version != "" {
					components = appendUnique(components, fmt.Sprintf("plugin:%s@%s", p.slug, p.version))
					findings = append(findings, matchVulns("WordPress", "plugin:"+p.slug, p.version, base)...)
				} else {
					components = appendUnique(components, "plugin:"+p.slug)
				}
			}
		}

		if stack == "Drupal" {
			for _, m := range drupalModule.FindAllStringSubmatch(body, -1) {
				components = appendUnique(components, "module:"+strings.ToLower(m[1]))
			}
		}

		if stack == "Joomla" {
			for _, m := range joomlaCom.FindAllStringSubmatch(body, -1) {
				components = appendUnique(components, "component:com_"+strings.ToLower(m[1]))
			}
		}

		if stack == "MediaWiki" {
			for _, m := range mediawikiExt.FindAllStringSubmatch(body, -1) {
				components = appendUnique(components, "extension:"+strings.ToLower(m[1]))
			}
		}

		if rules, ok := stackRules[strings.ToLower(stack)]; ok {
			findings = append(findings, checkPaths(validator, base, rules, baseline, stealth)...)
		}
	}

	if primary == "" || len(stacks) == 0 {
		// Even without a detected stack, run the generic probes; but only
		// emit a result when they actually produced something.
		generic := checkPaths(validator, base, genericRules, baseline, stealth)
		if len(generic) == 0 {
			return nil
		}
		findings = append(findings, generic...)
	} else {
		findings = append(findings, checkPaths(validator, base, genericRules, baseline, stealth)...)
	}

	if len(findings) == 0 && version == "" && len(components) == 0 {
		return nil
	}

	findings = dedupeFindings(findings)

	return &output.TechResult{
		URL:        host.URL,
		Stack:      strings.Join(stacks, ", "),
		Version:    version,
		DetectedBy: detectedBy,
		Components: components,
		Findings:   findings,
	}
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func dedupeFindings(findings []output.Finding) []output.Finding {
	seen := map[string]struct{}{}
	var out []output.Finding
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

func fetch(client *http.Client, url string, stealth bool) (string, int) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return "", 0
	}
	if stealth {
		req.Header.Set("User-Agent", output.RandomUA())
	} else {
		req.Header.Set("User-Agent", output.DefaultUA)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return string(body), resp.StatusCode
}

// detectStacks returns detected stack names in fingerprint-file priority order.
func detectStacks(body string) []string {
	load()
	lower := strings.ToLower(body)
	var stacks []string
	seen := map[string]bool{}
	for _, f := range fingerprints {
		if strings.Contains(lower, f.needle) && !seen[f.name] {
			seen[f.name] = true
			stacks = append(stacks, f.name)
		}
	}
	return stacks
}

// detectVersion extracts the stack version with minimal extra requests.
func detectVersion(client *http.Client, base, stack, body string, stealth bool) (string, string) {
	switch stack {
	case "WordPress":
		if m := wpEmojiVer.FindStringSubmatch(body); len(m) > 1 {
			if v := cleanVer(m[1]); v != "" {
				return v, "static asset query string"
			}
		}
		if m := wpGenVer.FindStringSubmatch(body); len(m) > 1 {
			return m[1], "generator meta tag"
		}
		if m := wpOrgVer.FindStringSubmatch(body); len(m) > 1 {
			return m[1], "feed link tag"
		}
		if b, _ := fetch(client, base+"/wp-links-opml.php", stealth); b != "" {
			if m := wpCoreVer.FindStringSubmatch(b); len(m) > 1 {
				return m[1], "/wp-links-opml.php"
			}
		}
		if b, _ := fetch(client, base+"/feed/", stealth); b != "" {
			if m := wpCoreVer.FindStringSubmatch(b); len(m) > 1 {
				return m[1], "/feed/"
			}
		}
	case "Drupal":
		if b, _ := fetch(client, base+"/CHANGELOG.txt", stealth); b != "" {
			if m := drupalChange.FindStringSubmatch(b); len(m) > 1 {
				return m[1], "/CHANGELOG.txt"
			}
		}
		if b, _ := fetch(client, base+"/core/CHANGELOG.txt", stealth); b != "" {
			if m := drupalChange.FindStringSubmatch(b); len(m) > 1 {
				return m[1], "/core/CHANGELOG.txt"
			}
		}
	case "Joomla":
		if b, _ := fetch(client, base+"/administrator/manifests/files/joomla.xml", stealth); b != "" {
			if m := joomlaXMLVer.FindStringSubmatch(b); len(m) > 1 {
				return m[1], "joomla.xml"
			}
		}
		if b, _ := fetch(client, base+"/README.txt", stealth); b != "" {
			if m := joomlaReadme.FindStringSubmatch(b); len(m) > 1 {
				return m[1], "/README.txt"
			}
		}
	case "Magento":
		if b, _ := fetch(client, base+"/magento_version", stealth); b != "" {
			if m := magentoVer.FindStringSubmatch(b); len(m) > 1 {
				return m[1], "/magento_version"
			}
		}
	case "Ghost":
		if m := ghostGenVer.FindStringSubmatch(body); len(m) > 1 {
			return m[1], "generator meta tag"
		}
	case "MediaWiki":
		if b, _ := fetch(client, base+"/api.php?action=query&meta=siteinfo&format=json", stealth); b != "" {
			if m := mediawikiVer.FindStringSubmatch(b); len(m) > 1 {
				return m[1], "/api.php siteinfo"
			}
		}
		if m := mediawikiVer.FindStringSubmatch(body); len(m) > 1 {
			return m[1], "homepage body"
		}
	case "Moodle":
		if b, _ := fetch(client, base+"/login/index.php", stealth); b != "" {
			if m := moodleVer.FindStringSubmatch(b); len(m) > 1 {
				return m[1], "/login/index.php"
			}
		}
		if m := moodleVer.FindStringSubmatch(body); len(m) > 1 {
			return m[1], "homepage body"
		}
	}
	return "", ""
}

// cleanVer normalises a detected version and returns "" when it is not a clean
// dotted numeric version (which cannot be range-matched).
func cleanVer(v string) string {
	v = strings.TrimSpace(v)
	if cleanVersion.MatchString(v) {
		return v
	}
	return ""
}

// matchVulns returns findings for version known to fall inside a vulnerable
// range of the given component.
func matchVulns(cms, target, version, asset string) []output.Finding {
	load()
	var fs []output.Finding
	if cleanVer(version) == "" {
		return fs
	}
	for _, r := range vulnRules {
		if !strings.EqualFold(r.cms, cms) || !strings.EqualFold(r.target, target) {
			continue
		}
		if !versionInRange(version, r.minVer, r.maxVer) {
			continue
		}
		fs = append(fs, output.Finding{
			Severity:      r.severity,
			Confidence:    output.ConfLow,
			Title:         r.title,
			AffectedAsset: asset,
			Description:   r.description,
			Evidence:      fmt.Sprintf("Detected %s %s %s (version-only match; no exploitation validated)", cms, target, version),
			Remediation:   r.remediation,
		})
	}
	return fs
}

// versionInRange reports whether version lies in [minVer, maxVer]; empty
// bounds are open-ended.
func versionInRange(version, minVer, maxVer string) bool {
	if minVer != "" && compareVersions(version, minVer) < 0 {
		return false
	}
	if maxVer != "" && compareVersions(version, maxVer) > 0 {
		return false
	}
	return true
}

// compareVersions compares dotted numeric versions lexicographically by
// numeric segment.
func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// discoverPlugins finds WordPress plugins from the homepage body and always
// re-checks the curated high-value slugs that have vulnerability rules.  The
// stable version is read from each plugin's readme.txt.
func discoverPlugins(client *http.Client, base, body string, stealth bool) []pluginInfo {
	slugs := map[string]bool{}
	for _, m := range pluginRe.FindAllStringSubmatch(body, -1) {
		slugs[strings.ToLower(m[1])] = true
	}
	for _, slug := range curatedWPPlugin {
		slugs[slug] = true
	}

	var out []pluginInfo
	for slug := range slugs {
		b, code := fetch(client, base+"/wp-content/plugins/"+slug+"/readme.txt", stealth)
		if code != 200 || b == "" {
			continue
		}
		ver := ""
		if m := pluginStable.FindStringSubmatch(b); len(m) > 1 {
			ver = strings.TrimSpace(m[1])
		}
		out = append(out, pluginInfo{slug: slug, version: ver})
	}
	return out
}

// checkPaths probes each rule against the host using the validation pipeline.
// Rules with a bodyMatch are only reported when the match appears; rules with
// a locationMatch are only reported when a redirect Location matches; rules
// with neither are reported on any response that passes validation (not a
// soft-404, not a SPA catch-all, not a redirect-to-root).
func checkPaths(validator *validation.Validator, base string, rules []pathRule, baseline *validation.BaselineProfile, _ bool) []output.Finding {
	load()
	var fs []output.Finding
	for _, r := range rules {
		target := base + r.path

		resp, err := validator.Validate(target, baseline)
		if err != nil {
			continue
		}

		hit := false
		switch {
		case r.bodyMatch != "":
			hit = strings.Contains(strings.ToLower(string(resp.Body)), strings.ToLower(r.bodyMatch))
		case r.locationMatch != "":
			hit = resp.IsRedirect && strings.Contains(strings.ToLower(resp.LocationHeader), strings.ToLower(r.locationMatch))
		default:
			// Use the validation pipeline instead of naive status checks.
			// The validator handles soft-404s, SPA catch-alls, redirects,
			// 401/403, and 5xx properly.
			hit = validation.ShouldReportFinding(resp, r.severity == output.Critical || r.severity == output.High)
		}
		if !hit {
			continue
		}

		fs = append(fs, output.Finding{
			Severity:        r.severity,
			Title:           r.title,
			AffectedAsset:   target,
			Description:     fmt.Sprintf("%s returned HTTP %d.", r.path, resp.FinalStatus),
			Evidence:        validation.EvidenceSummary(resp),
			Remediation:     fmt.Sprintf("Restrict or remove %s from public access.", r.path),
			ValidationState: output.ValidationState(validation.ValidationStateClass(resp, true)),
			FinalURL:        resp.FinalURL,
			OriginalStatus:  resp.OriginalStatus,
			FinalStatus:     resp.FinalStatus,
			RedirectChain:   validation.RedirectSummary(resp),
		})
	}
	return fs
}
