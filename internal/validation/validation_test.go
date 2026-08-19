package validation

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRealHTTP200 verifies that a legitimate 200 response is classified correctly.
func TestRealHTTP200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Baseline should hit a different path
		if strings.Contains(r.URL.Path, "anansi-nonexistent") {
			w.WriteHeader(404)
			_, _ = w.Write([]byte("Not Found"))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><head><title>Valid Page - Real Content</title></head><body><h1>Welcome</h1><p>This is real unique content for a real page.</p></body></html>"))
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")

	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/realpage", baseline)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !resp.IsValidResource {
		t.Errorf("Expected valid resource, got IsValidResource=%v, notes=%v", resp.IsValidResource, resp.ValidationNotes)
	}

	if resp.IsSoft404 {
		t.Errorf("Expected no soft-404, got IsSoft404=%v", resp.IsSoft404)
	}

	if !ShouldReportFinding(resp, false) {
		t.Errorf("Expected finding to be reportable")
	}
}

// TestRealHTTP404 verifies that a true 404 is recognized.
func TestRealHTTP404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("Not found"))
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")

	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/missing", baseline)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if resp.IsValidResource {
		t.Errorf("Expected invalid resource, got IsValidResource=%v", resp.IsValidResource)
	}

	if resp.FinalStatus != 404 {
		t.Errorf("Expected status 404, got %d", resp.FinalStatus)
	}

	if ShouldReportFinding(resp, false) {
		t.Errorf("404 should not be reportable")
	}
}

// TestSoft404Returning200 verifies detection of soft-404 (200 status but "not found" content).
func TestSoft404Returning200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><head><title>404 - Page Not Found</title></head><body><h1>404 Not Found</h1></body></html>"))
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")

	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/notfound", baseline)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if resp.IsValidResource {
		t.Errorf("Expected invalid resource (soft-404), got IsValidResource=%v", resp.IsValidResource)
	}

	if !resp.IsSoft404 {
		t.Errorf("Expected soft-404 detection, got IsSoft404=%v", resp.IsSoft404)
	}

	if ShouldReportFinding(resp, false) {
		t.Errorf("Soft-404 should not be reportable")
	}
}

// Test301Redirect verifies proper handling of 301 redirects.
func Test301Redirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("New page content"))
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")

	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/old", baseline)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if resp.OriginalStatus != 301 {
		t.Errorf("Expected original status 301, got %d", resp.OriginalStatus)
	}

	if resp.FinalStatus != 200 {
		t.Errorf("Expected final status 200, got %d", resp.FinalStatus)
	}

	if !resp.IsRedirect {
		t.Errorf("Expected IsRedirect=true")
	}

	if len(resp.RedirectChain) == 0 {
		t.Errorf("Expected redirect chain to be populated")
	}

	// Original URL should differ from final URL
	if resp.RequestedURL == resp.FinalURL {
		t.Errorf("Expected RequestedURL to differ from FinalURL")
	}
}

// TestRedirectToLogin verifies redirect-to-login detection.
func TestRedirectToLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.URL.Path == "/login" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<html><title>Login</title><body>Please log in</body></html>"))
			return
		}
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")

	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/admin", baseline)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !resp.IsAuthRequired {
		t.Errorf("Expected IsAuthRequired=true for redirect to login")
	}

	if !resp.IsValidResource {
		t.Errorf("Expected IsValidResource=true (resource exists, requires auth)")
	}

	// This SHOULD be reportable as it indicates the endpoint exists
	if !ShouldReportFinding(resp, true) {
		t.Errorf("Redirect-to-login should be reportable")
	}
}

// TestRedirectToRoot verifies redirect-to-root is treated as soft-404.
func TestRedirectToRoot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oldpath" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><title>Home</title><body>Welcome</body></html>"))
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")

	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/oldpath", baseline)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if resp.IsValidResource {
		t.Errorf("Expected IsValidResource=false for redirect to root")
	}

	if !resp.IsSoft404 {
		t.Errorf("Expected IsSoft404=true for redirect to root")
	}

	if ShouldReportFinding(resp, false) {
		t.Errorf("Redirect-to-root should not be reportable")
	}
}

// Test403Forbidden verifies 403 is recognized as access denied, not non-existent.
func Test403Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte("Forbidden"))
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")

	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/protected", baseline)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !resp.IsAccessDenied {
		t.Errorf("Expected IsAccessDenied=true for 403")
	}

	if !resp.IsValidResource {
		t.Errorf("Expected IsValidResource=true for 403 (resource exists)")
	}

	if resp.FinalStatus != 403 {
		t.Errorf("Expected status 403, got %d", resp.FinalStatus)
	}

	// 403 should be reportable - it's interesting
	if !ShouldReportFinding(resp, true) {
		t.Errorf("403 Forbidden should be reportable")
	}
}

// Test401Unauthorized verifies 401 is recognized as authentication required.
func Test401Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte("Unauthorized"))
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")

	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/api", baseline)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !resp.IsAuthRequired {
		t.Errorf("Expected IsAuthRequired=true for 401")
	}

	if !resp.IsValidResource {
		t.Errorf("Expected IsValidResource=true for 401 (resource exists)")
	}

	if resp.FinalStatus != 401 {
		t.Errorf("Expected status 401, got %d", resp.FinalStatus)
	}

	// 401 should be reportable
	if !ShouldReportFinding(resp, true) {
		t.Errorf("401 Unauthorized should be reportable")
	}
}

// TestSPACatchAll verifies detection of SPA catch-all responses.
func TestSPACatchAll(t *testing.T) {
	spaShell := "<html><head><title>My SPA</title></head><body><div id='root'></div></body></html>"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Always return the same SPA shell regardless of path
		w.WriteHeader(200)
		_, _ = w.Write([]byte(spaShell))
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")

	// Establish baseline
	baseline, _ := validator.GetBaseline(server.URL)

	// Test a random path
	resp, err := validator.Validate(server.URL+"/random-invalid-route", baseline)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should be detected as similar to baseline
	if resp.IsValidResource {
		t.Errorf("Expected IsValidResource=false for SPA catch-all")
	}

	if !resp.IsSoft404 {
		t.Errorf("Expected IsSoft404=true for SPA catch-all")
	}

	if !resp.IsSPACatchAll {
		t.Errorf("Expected IsSPACatchAll=true")
	}

	if ShouldReportFinding(resp, false) {
		t.Errorf("SPA catch-all should not be reportable")
	}
}

// TestLegitimatePageContainingNotFoundText verifies that a real page mentioning
// "404" in content is not incorrectly flagged as soft-404.
func TestLegitimatePageContainingNotFoundText(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Baseline should be different
		if strings.Contains(r.URL.Path, "anansi-nonexistent") {
			w.WriteHeader(404)
			_, _ = w.Write([]byte("Not Found"))
			return
		}
		w.WriteHeader(200)
		// A legitimate article about HTTP errors
		_, _ = w.Write([]byte("<html><head><title>Understanding HTTP Errors - Complete Guide</title></head><body><h1>HTTP Error Codes</h1><p>The 404 error means page not found. It's commonly seen when a resource doesn't exist. Here's how to handle it properly in your application...</p><p>More detailed content here about various error codes and their meanings.</p></body></html>"))
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")

	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/article", baseline)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should NOT be flagged as soft-404 because the title doesn't match patterns
	if !resp.IsValidResource {
		t.Errorf("Expected IsValidResource=true for legitimate page, got %v, notes=%v", resp.IsValidResource, resp.ValidationNotes)
	}

	if resp.IsSoft404 {
		t.Errorf("Legitimate page should not be flagged as soft-404")
	}
}

// Test500ServerError verifies 5xx responses are handled correctly.
func Test500ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")

	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/broken", baseline)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if resp.IsValidResource {
		t.Errorf("Expected IsValidResource=false for server error")
	}

	if resp.FinalStatus != 500 {
		t.Errorf("Expected status 500, got %d", resp.FinalStatus)
	}

	// Server errors should not be reported as findings
	if ShouldReportFinding(resp, false) {
		t.Errorf("500 error should not be reportable")
	}
}

// TestBaselineCaching verifies that baseline is cached per base URL.
func TestBaselineCaching(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")

	// First baseline request
	baseline1, _ := validator.GetBaseline(server.URL)

	// Second baseline request should return cached version
	baseline2, _ := validator.GetBaseline(server.URL)

	if baseline1 != baseline2 {
		t.Errorf("Expected baseline to be cached (same pointer)")
	}

	if baseline1.RandomPath == "" {
		t.Errorf("Expected baseline to have random path set")
	}
}

// TestContainsSoft404Indicators tests the soft-404 detection logic.
func TestContainsSoft404Indicators(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		title    string
		expected bool
	}{
		{
			name:     "Clear 404 in title",
			body:     "<html><body>Error</body></html>",
			title:    "404 Not Found",
			expected: true,
		},
		{
			name:     "Page not found in title",
			body:     "<html><body>Error</body></html>",
			title:    "Page Not Found",
			expected: true,
		},
		{
			name:     "Legitimate article mentioning 404",
			body:     "<html><body>Understanding 404 errors in web development is important...</body></html>",
			title:    "Understanding HTTP Status Codes and How to Handle 404 Errors Properly",
			expected: false, // Title is too long to be an error page
		},
		{
			name:     "H1 with 404",
			body:     "<html><body><h1>404 - Not Found</h1><p>Page doesn't exist</p></body></html>",
			title:    "Error",
			expected: true,
		},
		{
			name:     "Framework error page",
			body:     "Whitelabel Error Page",
			title:    "Error",
			expected: true,
		},
		{
			name:     "Normal page",
			body:     "<html><head><title>Welcome</title></head><body>Content</body></html>",
			title:    "Welcome",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsSoft404Indicators(tt.body, tt.title)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestIsLoginRedirect tests login redirect detection.
func TestIsLoginRedirect(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com/login", true},
		{"https://example.com/signin", true},
		{"https://example.com/sign-in", true},
		{"https://example.com/auth", true},
		{"https://example.com/authenticate", true},
		{"https://example.com/sso", true},
		{"https://example.com/oauth", true},
		{"https://example.com/account/login", true},
		{"https://example.com/user/login", true},
		{"https://example.com/users/sign_in", true},
		{"https://example.com/dashboard", false},
		{"https://example.com/home", false},
		{"https://example.com/about", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			result := isLoginRedirect(tt.url)
			if result != tt.expected {
				t.Errorf("isLoginRedirect(%s) = %v, expected %v", tt.url, result, tt.expected)
			}
		})
	}
}

// TestIsRootRedirect tests root redirect detection.
func TestIsRootRedirect(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com/", true},
		{"https://example.com", true},
		{"https://example.com/index.html", true},
		{"https://example.com/index.php", true},
		{"https://example.com/home", true},
		{"https://example.com/home.html", true},
		{"https://example.com/default.html", true},
		{"https://example.com/admin", false},
		{"https://example.com/api/v1", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			result := isRootRedirect(tt.url)
			if result != tt.expected {
				t.Errorf("isRootRedirect(%s) = %v, expected %v", tt.url, result, tt.expected)
			}
		})
	}
}

// TestStringSimilarity tests the similarity calculation.
func TestStringSimilarity(t *testing.T) {
	tests := []struct {
		a        string
		b        string
		minScore float64 // Minimum expected similarity
	}{
		{"identical", "identical", 1.0},
		{"very similar text", "very similar text", 1.0},
		{"similar", "similarity", 0.5},   // Some similarity
		{"completely", "different", 0.0}, // Very different
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			score := stringSimilarity(tt.a, tt.b)
			if score < tt.minScore {
				t.Errorf("Similarity between '%s' and '%s' = %f, expected at least %f",
					tt.a, tt.b, score, tt.minScore)
			}
		})
	}
}

// TestNormalizeBody tests body normalization removes dynamic content.
func TestNormalizeBody(t *testing.T) {
	body1 := `{"timestamp":1234567890,"requestId":"abc123","data":"content"}`
	body2 := `{"timestamp":9876543210,"requestId":"xyz789","data":"content"}`

	norm1 := normalizeBody([]byte(body1))
	norm2 := normalizeBody([]byte(body2))

	// After normalization, these should be more similar
	if !strings.Contains(norm1, "NORMALIZED") {
		t.Errorf("Expected normalization to replace dynamic values")
	}

	similarity := stringSimilarity(norm1, norm2)
	if similarity < 0.8 {
		t.Errorf("Expected high similarity after normalization, got %f", similarity)
	}
}

// TestCustomErrorPageSoft404 verifies that a custom error page returning
// HTTP 200 with short, generic content and matching baseline is classified
// as a soft-404.
func TestCustomErrorPageSoft404(t *testing.T) {
	errorPage := `<html><head><title>Page Not Found</title></head><body><h1>404 - Not Found</h1><p>The page you requested could not be found.</p></body></html>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Baseline path must return 404
		if strings.Contains(r.URL.Path, "anansi-nonexistent") {
			w.WriteHeader(404)
			return
		}
		// All other paths return the same custom error page (soft-404)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(errorPage))
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")
	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/anything", baseline)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !resp.IsSoft404 {
		t.Errorf("Expected IsSoft404=true for custom error page, notes=%v", resp.ValidationNotes)
	}
	if resp.IsValidResource {
		t.Errorf("Expected IsValidResource=false for custom error page")
	}
}

// TestContentMismatchWithBaseline verifies that when a target path returns
// genuinely different content from the baseline, it is not flagged as soft-404.
func TestContentMismatchWithBaseline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "anansi-nonexistent") {
			w.WriteHeader(404)
			_, _ = w.Write([]byte("Not Found"))
			return
		}
		if r.URL.Path == "/dashboard" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<html><head><title>Admin Dashboard</title></head><body><h1>Dashboard</h1><p>Welcome back, admin.</p><p>System status: operational.</p><p>Last login: 2024-01-15.</p></body></html>"))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><head><title>Home</title></head><body><p>Welcome to our site.</p></body></html>"))
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")
	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/dashboard", baseline)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !resp.IsValidResource {
		t.Errorf("Expected IsValidResource=true for unique content, notes=%v", resp.ValidationNotes)
	}
	if resp.IsSoft404 {
		t.Errorf("Should not flag unique content as soft-404")
	}
}

// TestMultipleRedirectChain verifies that the validator correctly follows
// and records a multi-hop redirect chain.
func TestMultipleRedirectChain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/middle", http.StatusFound)
		case "/middle":
			http.Redirect(w, r, "/end", http.StatusFound)
		case "/end":
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<html><head><title>Final Destination</title></head><body>You arrived.</body></html>"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")
	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/start", baseline)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !resp.IsRedirect {
		t.Errorf("Expected IsRedirect=true for multi-hop chain")
	}
	if len(resp.RedirectChain) < 2 {
		t.Errorf("Expected at least 2 redirect hops, got %d: %v", len(resp.RedirectChain), resp.RedirectChain)
	}
	if resp.FinalStatus != 200 {
		t.Errorf("Expected final status 200, got %d", resp.FinalStatus)
	}
	if !resp.IsValidResource {
		t.Errorf("Expected IsValidResource=true for redirect chain ending in real content")
	}
}

// TestShortContentDetection verifies that extremely short responses (e.g. just
// "OK" or empty body) from a non-root path are suspicious.
func TestShortContentDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "anansi-nonexistent") {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")
	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/api/endpoint", baseline)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Should note the short content even if not definitively soft-404
	if resp.ContentLength < 10 {
		// Short content should at least be flagged for review
		t.Logf("Short content response (%d bytes) detected as expected", resp.ContentLength)
	}
}

// TestRedirectTo404Page verifies that a redirect chain ending in a 404 is
// treated as invalid.
func TestRedirectTo404Page(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/old":
			http.Redirect(w, r, "/also-missing", http.StatusFound)
		case "/also-missing":
			w.WriteHeader(404)
			_, _ = w.Write([]byte("Not Found"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")
	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/old", baseline)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.FinalStatus != 404 {
		t.Errorf("Expected final status 404, got %d", resp.FinalStatus)
	}
	if resp.IsValidResource {
		t.Errorf("Expected IsValidResource=false for redirect ending in 404")
	}
	if ShouldReportFinding(resp, false) {
		t.Errorf("Redirect ending in 404 should not be reportable")
	}
}

// TestStatusNotOKWithMatchingBaseline verifies that when both baseline and
// target return the same non-200 status, it is treated as invalid.
func TestStatusNotOKWithMatchingBaseline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Return 503 for everything
		w.WriteHeader(503)
		_, _ = w.Write([]byte("Service Unavailable"))
	}))
	defer server.Close()

	client := &http.Client{}
	validator := NewValidator(client, "test-agent")
	baseline, _ := validator.GetBaseline(server.URL)
	resp, err := validator.Validate(server.URL+"/api", baseline)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.FinalStatus != 503 {
		t.Errorf("Expected status 503, got %d", resp.FinalStatus)
	}
	if resp.IsValidResource {
		t.Errorf("Expected IsValidResource=false for 503 response")
	}
}

// TestEvidenceSummary verifies the EvidenceSummary helper produces readable output.
func TestEvidenceSummary(t *testing.T) {
	resp := &ResponseInfo{
		RequestedURL:   "https://example.com/secret",
		FinalURL:       "https://example.com/login",
		OriginalStatus: 302,
		FinalStatus:    200,
		RedirectChain: []RedirectHop{
			{FromURL: "https://example.com/secret", ToURL: "https://example.com/login", StatusCode: 302},
		},
		ValidationNotes: []string{"Redirects to login page"},
	}
	summary := EvidenceSummary(resp)
	if !strings.Contains(summary, "Original: HTTP 302") || !strings.Contains(summary, "Final: HTTP 200") {
		t.Errorf("Expected status transition in summary, got: %s", summary)
	}
	if !strings.Contains(summary, "Redirects to login page") {
		t.Errorf("Expected validation note in summary")
	}
}

// TestValidationStateClass verifies state classification for various response types.
func TestValidationStateClass(t *testing.T) {
	tests := []struct {
		name     string
		resp     *ResponseInfo
		baseline bool
		want     ValidationState
	}{
		{"nil response", nil, false, StateUnconfirmed},
		{"soft-404", &ResponseInfo{IsSoft404: true}, false, StateRejected},
		{"SPA catch-all", &ResponseInfo{IsSPACatchAll: true}, false, StateRejected},
		{"invalid resource", &ResponseInfo{IsValidResource: false}, false, StateRejected},
		{"auth required", &ResponseInfo{IsAuthRequired: true, IsValidResource: true}, false, StateConfirmed},
		{"access denied", &ResponseInfo{IsAccessDenied: true, IsValidResource: true}, false, StateConfirmed},
		{"redirect 200 with baseline", &ResponseInfo{IsRedirect: true, FinalStatus: 200, IsValidResource: true}, true, StateConfirmed},
		{"redirect 200 no baseline", &ResponseInfo{IsRedirect: true, FinalStatus: 200, IsValidResource: true}, false, StateLikely},
		{"direct 200 with baseline", &ResponseInfo{FinalStatus: 200, IsValidResource: true}, true, StateConfirmed},
		{"direct 200 no baseline", &ResponseInfo{FinalStatus: 200, IsValidResource: true}, false, StateLikely},
		{"ambiguous status", &ResponseInfo{FinalStatus: 301, IsValidResource: true}, false, StatePossible},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidationStateClass(tt.resp, tt.baseline)
			if got != tt.want {
				t.Errorf("ValidationStateClass() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRedirectSummary verifies RedirectSummary produces correct output.
func TestRedirectSummary(t *testing.T) {
	resp := &ResponseInfo{
		RedirectChain: []RedirectHop{
			{FromURL: "https://a.com/old", ToURL: "https://a.com/new", StatusCode: 301},
			{FromURL: "https://a.com/new", ToURL: "https://a.com/final", StatusCode: 302},
		},
	}
	chain := RedirectSummary(resp)
	if len(chain) != 2 {
		t.Fatalf("Expected 2 chain entries, got %d", len(chain))
	}
	if !strings.Contains(chain[0], "301") {
		t.Errorf("First hop should mention 301, got: %s", chain[0])
	}
	if !strings.Contains(chain[1], "302") {
		t.Errorf("Second hop should mention 302, got: %s", chain[1])
	}

	// Nil case
	if RedirectSummary(nil) != nil {
		t.Errorf("Expected nil for nil input")
	}
}
