package headers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-anansi/internal/httpclient"
	"github.com/QYVORA/qyvora-anansi/internal/output"
)

// TestAuditMissingSecurityHeaders flags every absent hardening header.
func TestAuditMissingSecurityHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
	}))
	defer srv.Close()

	res := auditURL(srv.Client(), srv.URL, false)
	if !res.Success {
		t.Fatalf("audit failed: %s", res.Error)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected findings for a bare server")
	}
	absent := map[string]bool{}
	for _, f := range res.Findings {
		absent[f.Title] = true
	}
	for _, expected := range []string{
		"HSTS", "Content-Security-Policy", "X-Frame-Options", "Referrer-Policy",
	} {
		found := false
		for title := range absent {
			if strings.Contains(title, expected) {
				found = true
			}
		}
		if !found {
			t.Errorf("expected a finding containing %q, got %v", expected, absent)
		}
	}
}

// TestAuditPresentHeadersProducesNoFindings.
func TestAuditPresentHeadersProducesNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=()")
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}))
	defer srv.Close()

	res := auditURL(srv.Client(), srv.URL, false)
	if !res.Success {
		t.Fatalf("audit failed: %s", res.Error)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(res.Findings))
	}
}

// TestCORSWildcard flags Access-Control-Allow-Origin: *.
func TestCORSWildcard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}))
	defer srv.Close()

	res := auditURL(srv.Client(), srv.URL, false)
	if len(res.Findings) == 0 {
		t.Fatal("expected a CORS finding")
	}
	var cors bool
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "CORS") {
			cors = true
			if f.Severity != output.Medium {
				t.Errorf("wildcard CORS severity = %s, want MEDIUM", f.Severity)
			}
		}
	}
	if !cors {
		t.Error("no CORS finding for wildcard origin")
	}
}

// TestCORSOriginReflection escalates to HIGH.
func TestCORSOriginReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}))
	defer srv.Close()

	res := auditURL(srv.Client(), srv.URL, false)
	var found bool
	for _, f := range res.Findings {
		if f.Title == "CORS Origin Reflection" {
			found = true
			if f.Severity != output.High {
				t.Errorf("reflection severity = %s, want HIGH", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected a CORS origin reflection finding")
	}
}

// TestCORSReflectionWithCredentials escalates to CRITICAL.
func TestCORSReflectionWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}))
	defer srv.Close()

	res := auditURL(srv.Client(), srv.URL, false)
	var found bool
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "Credentials") {
			found = true
			if f.Severity != output.Critical {
				t.Errorf("reflection+credentials severity = %s, want CRITICAL", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected a CORS reflection with credentials finding")
	}
}

// TestRunConcurrent gathers results across hosts and dedups per URL.
func TestRunConcurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	live := []output.ProbeResult{
		{URL: srv.URL, IsAlive: true},
		{URL: srv.URL, IsAlive: true},
	}
	results := Run(nil, live, 5, 4, 0, false)
	if len(results) != 2 {
		t.Errorf("Run returned %d results, want 2", len(results))
	}
	for _, r := range results {
		if !r.Success || r.URL != srv.URL {
			t.Errorf("unexpected result %+v", r)
		}
	}
}

// TestLoadHeaderRulesParsesEmbeddedWordlist ensures the rules file is intact
// and has at least the classic OWASP top four.
func TestLoadHeaderRulesParsesEmbeddedWordlist(t *testing.T) {
	loadHeaderRules()
	if len(securityHeaders) == 0 {
		t.Fatal("no security headers loaded from embedded wordlist")
	}
	set := map[string]bool{}
	for _, h := range securityHeaders {
		set[strings.ToLower(h)] = true
	}
	for _, required := range []string{
		"strict-transport-security",
		"content-security-policy",
		"x-frame-options",
		"x-content-type-options",
	} {
		if !set[required] {
			t.Errorf("embedded rules missing %q", required)
		}
	}
}

// TestAuditURLSkipsErrorResponses verifies no findings are produced for 5xx responses.
func TestAuditURLSkipsErrorResponses(t *testing.T) {
	// Server that returns 500 with no security headers should produce zero findings
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	result := auditURL(client, srv.URL, false)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.Success {
		t.Fatal("expected success")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings on 5xx response, got %d: %v", len(result.Findings), result.Findings)
	}
}

// TestAuditErrorResult surfaces request failures without panicking.
func TestAuditErrorResult(t *testing.T) {
	res := auditURL(httpclient.NewFollowRedirects(1), "http://127.0.0.1:1/", false)
	if res.Success {
		t.Error("expected failure against a closed port")
	}
	if res.Error == "" {
		t.Error("expected an error message")
	}
}
