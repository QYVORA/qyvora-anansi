package techstack

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-anansi/internal/httpclient"
	"github.com/QYVORA/qyvora-anansi/internal/output"
	"github.com/QYVORA/qyvora-anansi/internal/validation"
)

func TestDetectStacks(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"wordpress", `<meta name="generator" content="WordPress 6.4.3" />`, []string{"WordPress"}},
		{"drupal", `<script src="/core/misc/drupal.js"></script>`, []string{"Drupal"}},
		{"joomla", `<script src="/media/system/js/core.js"></script>`, []string{"Joomla"}},
		{"magento", `<script src="/static/version/123/frontend/.."></script>`, []string{"Magento"}},
		{"ghost", `<script src="/ghost/assets/built/"></script>`, []string{"Ghost"}},
		{"moodle", `var M = { cfg: {} }; <link href="/theme/moodle/"></link>`, []string{"Moodle"}},
		{"mediawiki", `<script>mw.config.set({"wgVersion":"1.35.1"});</script>`, []string{"MediaWiki"}},
		{"laravel", `XSRF-TOKEN, laravel_session`, []string{"Laravel"}},
		{"nextjs", `<script src="/_next/static/chunks/main.js"></script>`, []string{"Next.js"}},
		{"none", "plain static page", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectStacks(tt.body)
			if len(got) != len(tt.want) {
				t.Fatalf("detectStacks() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("detectStacks()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"6.4.3", "6.4.3", 0},
		{"6.4.3", "6.4.2", 1},
		{"6.4.2", "6.4.3", -1},
		{"8.5.1", "8.5", 1},
		{"7.58", "7.58.0", 0},
		{"3.4.5", "3.5", -1},
	}
	for _, tt := range tests {
		if got := compareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestVersionInRange(t *testing.T) {
	if !versionInRange("6.4.2", "", "6.4.2") {
		t.Error("6.4.2 should match max bound 6.4.2")
	}
	if versionInRange("6.4.3", "", "6.4.2") {
		t.Error("6.4.3 should exceed max bound 6.4.2")
	}
	if !versionInRange("8.3.0", "8.0", "8.5.0") {
		t.Error("8.3.0 should be inside [8.0, 8.5.0]")
	}
	if versionInRange("7.9", "8.0", "8.5.0") {
		t.Error("7.9 should be below min bound 8.0")
	}
	if !versionInRange("6.4.3", "", "") {
		t.Error("empty bounds should always match")
	}
}

func TestMatchVulns(t *testing.T) {
	load()
	fs := matchVulns("WordPress", "core", "6.4.2", "https://example.com")
	if len(fs) == 0 {
		t.Fatal("expected at least one vulnerability match for WordPress 6.4.2")
	}
	found := false
	for _, f := range fs {
		if strings.Contains(f.Title, "6.4.3") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the <6.4.3 CVE-2024-31210 rule to match 6.4.2, got %v", fs)
	}
	fs = matchVulns("WordPress", "core", "6.5.0", "https://example.com")
	if len(fs) != 0 {
		t.Errorf("WordPress 6.5.0 should not match any rules, got %v", fs)
	}
	fs = matchVulns("WordPress", "core", "not-a-version", "https://example.com")
	if len(fs) != 0 {
		t.Errorf("unclean versions must not match, got %v", fs)
	}
}

func TestCleanVer(t *testing.T) {
	if got := cleanVer("6.4.3"); got != "6.4.3" {
		t.Errorf("cleanVer(6.4.3) = %q", got)
	}
	if got := cleanVer("abc123"); got != "" {
		t.Errorf("cleanVer(abc123) should be empty, got %q", got)
	}
}

func TestDetectVersionWordPress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/wp-links-opml.php":
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
<channel>
<generator>https://wordpress.org/?v=5.7.2</generator>
</channel>
</rss>`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	client := httpclient.NewFollowRedirects(5)
	ver, src := detectVersion(client, srv.URL, "WordPress", "no version in body", false)
	if ver != "5.7.2" {
		t.Fatalf("detectVersion() = %q, want 5.7.2", ver)
	}
	if !strings.Contains(src, "wp-links-opml") {
		t.Errorf("unexpected source %q", src)
	}
}

func TestDetectVersionMagento(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/magento_version" {
			_, _ = w.Write([]byte("Magento/2.4.3-p1 (Community)"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	client := httpclient.NewFollowRedirects(5)
	ver, src := detectVersion(client, srv.URL, "Magento", "", false)
	if ver != "2.4.3-p1" {
		t.Fatalf("detectVersion() = %q, want 2.4.3-p1", ver)
	}
	if !strings.Contains(src, "magento_version") {
		t.Errorf("unexpected source %q", src)
	}
}

func TestDetectVersionGhostGenerator(t *testing.T) {
	body := `<meta name="generator" content="Ghost 4.48.9" />`
	ver, src := detectVersion(httpclient.NewFollowRedirects(5), "http://x", "Ghost", body, false)
	if ver != "4.48.9" {
		t.Fatalf("detectVersion() = %q, want 4.48.9", ver)
	}
	if !strings.Contains(src, "generator") {
		t.Errorf("unexpected source %q", src)
	}
}

func TestDetectVersionMediaWiki(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api.php" {
			_, _ = w.Write([]byte(`{"query":{"general":{"generator":"MediaWiki 1.35.1"}}}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	client := httpclient.NewFollowRedirects(5)
	ver, _ := detectVersion(client, srv.URL, "MediaWiki", "", false)
	if ver != "1.35.1" {
		t.Fatalf("detectVersion() = %q, want 1.35.1", ver)
	}
}

// TestMatchVulnsLowConfidence verifies that version-only CVE findings have Low confidence.
func TestMatchVulnsLowConfidence(t *testing.T) {
	load()
	// Create a finding via matchVulns - it should have Low confidence
	findings := matchVulns("WordPress", "core", "5.8", "https://example.com")
	// If there are any findings, they should all be Low confidence
	for _, f := range findings {
		if f.Confidence != output.ConfLow {
			t.Errorf("expected Low confidence for version-only CVE finding, got %s", f.Confidence)
		}
		if !strings.Contains(f.Evidence, "version-only") {
			t.Errorf("expected evidence to note version-only match, got: %s", f.Evidence)
		}
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one version-only CVE finding for WordPress 5.8")
	}
}

func TestMatchVulnsMagento(t *testing.T) {
	load()
	fs := matchVulns("Magento", "core", "2.4.2", "https://example.com")
	if len(fs) == 0 {
		t.Fatal("expected Magento CVE-2022-24086 match for 2.4.2")
	}
	found := false
	for _, f := range fs {
		if strings.Contains(f.Title, "CVE-2022-24086") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CVE-2022-24086 rule to match, got %v", fs)
	}
	// patched -p1 build should not be range-matched
	fs = matchVulns("Magento", "core", "2.4.3-p1", "https://example.com")
	if len(fs) != 0 {
		t.Errorf("Magento 2.4.3-p1 (patched build) must not match, got %v", fs)
	}
}

func TestAuditHostMagentoStackRules(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><head><link rel="stylesheet" href="/static/version/123/frontend.css"></head></html>`))
	})
	mux.HandleFunc("/app/etc/env.php", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<?php return ['crypt' => ['key' => 'SECRET']];"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	host := output.ProbeResult{FQDN: "magento.test", URL: srv.URL, IsAlive: true}
	follow := httpclient.NewFollowRedirects(5)
	noRedirect := httpclient.NewNoRedirect(5)

	tr := auditHost(follow, noRedirect, host, false)
	if tr == nil {
		t.Fatal("auditHost returned nil")
	}
	if !strings.Contains(tr.Stack, "Magento") {
		t.Errorf("expected Magento stack, got %q", tr.Stack)
	}
	foundEnv := false
	for _, f := range tr.Findings {
		if strings.Contains(f.Title, "Env Config") {
			foundEnv = true
		}
	}
	if !foundEnv {
		t.Errorf("expected env.php finding, got %+v", tr.Findings)
	}
}

func TestCheckPathsBodyMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/xmlrpc.php":
			_, _ = w.Write([]byte("XML-RPC server accepts POST requests only."))
		case "/ok.txt":
			w.WriteHeader(200)
		case "/missing.txt":
			w.WriteHeader(404)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	ua := output.DefaultUA
	validator := validation.NewValidator(httpclient.NewNoRedirect(5), ua)
	baseline, _ := validator.GetBaseline(srv.URL)

	rules := []pathRule{
		{path: "/xmlrpc.php", title: "XML-RPC", severity: output.Medium, bodyMatch: "XML-RPC server accepts POST requests only"},
		{path: "/missing.txt", title: "missing", severity: output.High},
		{path: "/ok.txt", title: "ok", severity: output.Low},
	}
	fs := checkPaths(validator, srv.URL, rules, baseline, false)
	if len(fs) != 2 {
		t.Fatalf("expected 2 findings (xmlrpc + ok), got %d: %+v", len(fs), fs)
	}
}

func TestCheckPathsLocationMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.URL.RawQuery == "author=1" {
			w.Header().Set("Location", "/author/admin/")
			w.WriteHeader(301)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	ua := output.DefaultUA
	validator := validation.NewValidator(httpclient.NewNoRedirect(5), ua)
	baseline, _ := validator.GetBaseline(srv.URL)
	rules := []pathRule{{path: "/?author=1", title: "User Enum", severity: output.High, locationMatch: "/author/"}}
	fs := checkPaths(validator, srv.URL, rules, baseline, false)
	if len(fs) != 1 {
		t.Fatalf("expected user enumeration finding, got %d: %+v", len(fs), fs)
	}
}

func TestDedupeHostsPrefersHTTPS(t *testing.T) {
	hosts := dedupeHosts([]output.ProbeResult{
		{FQDN: "a.example.com", URL: "http://a.example.com", IsAlive: true},
		{FQDN: "a.example.com", URL: "https://a.example.com", IsAlive: true},
		{FQDN: "b.example.com", URL: "https://b.example.com", IsAlive: true},
		{FQDN: "c.example.com", IsAlive: false},
	})
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}
	for _, h := range hosts {
		if !strings.HasPrefix(h.URL, "https://") {
			t.Errorf("expected https preference, got %s", h.URL)
		}
	}
}

// TestAuditHostWordPress simulates a full WordPress stack and verifies the
// deep audit surfaces version disclosure, a known-vulnerable version match,
// a vulnerable plugin, user enumeration, and exposed debug log.
func TestAuditHostWordPress(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.URL.RawQuery == "author=1" {
			w.Header().Set("Location", "/author/admin/")
			w.WriteHeader(301)
			return
		}
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head>
<meta name="generator" content="WordPress 6.0.2" />
<link rel="stylesheet" href="/wp-content/themes/twentytwentytwo/style.css">
<script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.0.2"></script>
</head><body>
<a href="/wp-content/plugins/elementor/assets/css/frontend.min.css?ver=3.10.0">css</a>
</body></html>`))
		default:
			w.WriteHeader(404)
		}
	})
	mux.HandleFunc("/wp-links-opml.php", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<rss><channel><generator>https://wordpress.org/?v=6.0.2</generator></channel></rss>`))
	})
	mux.HandleFunc("/xmlrpc.php", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("XML-RPC server accepts POST requests only."))
	})
	mux.HandleFunc("/wp-json/wp/v2/users", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"id":1,"name":"admin","slug":"admin"}]`))
	})
	mux.HandleFunc("/wp-content/debug.log", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("PHP Fatal error: Out of memory\n"))
	})
	mux.HandleFunc("/wp-content/plugins/elementor/readme.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("=== Elementor ===\nStable tag: 3.10.0\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	host := output.ProbeResult{FQDN: "wordpress.test", URL: srv.URL, IsAlive: true}
	follow := httpclient.NewFollowRedirects(5)
	noRedirect := httpclient.NewNoRedirect(5)

	tr := auditHost(follow, noRedirect, host, false)
	if tr == nil {
		t.Fatal("auditHost returned nil")
	}
	if !strings.Contains(tr.Stack, "WordPress") {
		t.Errorf("expected WordPress stack, got %q", tr.Stack)
	}
	if tr.Version != "6.0.2" {
		t.Errorf("expected version 6.0.2, got %q", tr.Version)
	}

	titles := map[string]bool{}
	for _, f := range tr.Findings {
		titles[f.Title] = true
	}
	wantTitles := []string{
		"WordPress < 6.0.3 - SQL Injection & Stored XSS (CVE-2022-43473, CVE-2022-43474)",
		"Elementor < 3.14.1 - Unauthenticated Account Takeover (CVE-2023-32243)",
		"WordPress REST API User Enumeration",
		"WordPress User Enumeration via Author Archive",
		"Exposed WordPress Debug Log",
		"WordPress XML-RPC Enabled (Brute-Force & DDoS Vector)",
	}
	for _, want := range wantTitles {
		if !titles[want] {
			t.Errorf("missing expected finding: %s (have %v)", want, titles)
		}
	}

	foundPlugin := false
	for _, c := range tr.Components {
		if c == "plugin:elementor@3.10.0" {
			foundPlugin = true
		}
	}
	if !foundPlugin {
		t.Errorf("expected plugin:elementor@3.10.0 component, got %v", tr.Components)
	}
}
