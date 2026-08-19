// Package validation provides HTTP response classification, soft-404 detection,
// redirect chain analysis, and baseline comparison to eliminate false positives.
//
// The core principle: HTTP 200 does not automatically mean "valid resource exists."
// Modern web applications frequently return 200 for custom error pages, SPA
// catch-all routes, and redirect-to-login flows. This package implements the
// detection pipeline: RAW RESPONSE → NORMALIZATION → VALIDATION → CLASSIFICATION.
package validation

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ValidationState describes the confidence level of a finding based on
// response validation. A finding should not be reported as confirmed
// merely because HTTP 200 was returned.
type ValidationState string

const (
	// StateConfirmed means the response was validated against baselines and
	// confirmed as a real, distinct resource (not a soft-404 or catch-all).
	StateConfirmed ValidationState = "confirmed"
	// StateLikely means the response passed basic checks but could not be
	// fully validated against a baseline (e.g. no baseline available).
	StateLikely ValidationState = "likely"
	// StatePossible means the response has some indicators of being a real
	// resource but also has ambiguous signals.
	StatePossible ValidationState = "possible"
	// StateUnconfirmed means the finding is based on raw observation only
	// and has not been validated.
	StateUnconfirmed ValidationState = "unconfirmed"
	// StateRejected means the finding was evaluated and determined to be
	// a false positive (soft-404, SPA catch-all, redirect-to-login, etc.).
	StateRejected ValidationState = "rejected"
)

// ResponseInfo captures complete HTTP response metadata including redirect chains,
// normalized content, and validation state. It preserves the distinction between
// the original request/response and any final response after redirects.
type ResponseInfo struct {
	// Request information
	RequestedURL string
	Method       string

	// Original response (before following redirects)
	OriginalStatus int
	OriginalURL    string

	// Final response (after following redirects, if any)
	FinalStatus   int
	FinalURL      string
	RedirectChain []RedirectHop
	RedirectCount int

	// Response content
	Headers       http.Header
	ContentType   string
	ContentLength int64
	Body          []byte
	BodyHash      string // SHA-256 of normalized body

	// Extracted metadata
	Title          string
	ServerHeader   string
	LocationHeader string

	// Validation results
	IsValidResource bool
	IsSoft404       bool
	IsRedirect      bool
	IsAuthRequired  bool
	IsAccessDenied  bool
	IsSPACatchAll   bool
	ValidationNotes []string

	// Timing
	ResponseTimeMs int64
}

// RedirectHop represents one step in a redirect chain.
type RedirectHop struct {
	FromURL    string
	ToURL      string
	StatusCode int
}

// BaselineProfile contains fingerprints of responses to nonexistent resources,
// used to detect soft-404s and SPA catch-alls.
type BaselineProfile struct {
	RandomPath      string
	StatusCode      int
	ContentLength   int
	BodyHash        string
	Title           string
	NormalizedBody  string
	HasSoft404Words bool
	Timestamp       time.Time
}

// Validator performs HTTP response validation and classification.
type Validator struct {
	client          *http.Client
	baselineCache   map[string]*BaselineProfile
	userAgent       string
	maxBodySize     int64
	followRedirects bool
}

// NewValidator creates a validator with default settings.
func NewValidator(client *http.Client, userAgent string) *Validator {
	return &Validator{
		client:          client,
		baselineCache:   make(map[string]*BaselineProfile),
		userAgent:       userAgent,
		maxBodySize:     8192, // 8KB max for validation
		followRedirects: true,
	}
}

// WithMaxBodySize sets the maximum body size to read for validation.
func (v *Validator) WithMaxBodySize(size int64) *Validator {
	v.maxBodySize = size
	return v
}

// GetBaseline establishes a baseline by probing a random nonexistent path.
// The baseline is cached per base URL to avoid repeated requests.
func (v *Validator) GetBaseline(baseURL string) (*BaselineProfile, error) {
	// Check cache first
	if cached, exists := v.baselineCache[baseURL]; exists {
		return cached, nil
	}

	// Generate random nonexistent path
	randomPath := fmt.Sprintf("/qyvora-anansi-nonexistent-%d-%d", time.Now().UnixNano(), time.Now().Unix())
	testURL := strings.TrimRight(baseURL, "/") + randomPath

	// Fetch baseline response
	resp, err := v.fetchWithRedirects(testURL, false)
	if err != nil {
		// If baseline fetch fails, return a default profile
		return &BaselineProfile{
			RandomPath: randomPath,
			StatusCode: 404,
			Timestamp:  time.Now(),
		}, nil
	}

	normalized := normalizeBody(resp.Body)

	baseline := &BaselineProfile{
		RandomPath:      randomPath,
		StatusCode:      resp.FinalStatus,
		ContentLength:   len(resp.Body),
		BodyHash:        resp.BodyHash,
		Title:           resp.Title,
		NormalizedBody:  normalized,
		HasSoft404Words: containsSoft404Indicators(string(resp.Body), resp.Title),
		Timestamp:       time.Now(),
	}

	v.baselineCache[baseURL] = baseline
	return baseline, nil
}

// Validate performs complete validation of an HTTP request, including baseline
// comparison, soft-404 detection, redirect analysis, and SPA catch-all detection.
func (v *Validator) Validate(targetURL string, baseline *BaselineProfile) (*ResponseInfo, error) {
	// Fetch response with redirect tracking
	resp, err := v.fetchWithRedirects(targetURL, true)
	if err != nil {
		return nil, err
	}

	// Perform classification
	v.classifyResponse(resp, baseline)

	return resp, nil
}

// fetchWithRedirects performs an HTTP GET and tracks redirects manually.
func (v *Validator) fetchWithRedirects(targetURL string, trackRedirects bool) (*ResponseInfo, error) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", v.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	start := time.Now()

	// Use a custom client that doesn't follow redirects for the first request
	noRedirectClient := &http.Client{
		Timeout:   v.client.Timeout,
		Transport: v.client.Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	elapsed := time.Since(start).Milliseconds()

	// Read body
	body, _ := io.ReadAll(io.LimitReader(resp.Body, v.maxBodySize))

	info := &ResponseInfo{
		RequestedURL:   targetURL,
		Method:         "GET",
		OriginalStatus: resp.StatusCode,
		OriginalURL:    targetURL,
		FinalStatus:    resp.StatusCode,
		FinalURL:       resp.Request.URL.String(),
		Headers:        resp.Header.Clone(),
		ContentType:    resp.Header.Get("Content-Type"),
		ContentLength:  resp.ContentLength,
		Body:           body,
		BodyHash:       hashBody(body),
		ServerHeader:   resp.Header.Get("Server"),
		LocationHeader: resp.Header.Get("Location"),
		ResponseTimeMs: elapsed,
		IsRedirect:     isRedirectStatus(resp.StatusCode),
	}

	// Extract title if HTML
	if strings.Contains(info.ContentType, "text/html") {
		info.Title = extractTitle(body)
	}

	// Handle redirects if requested and if this is a redirect
	if trackRedirects && info.IsRedirect && info.LocationHeader != "" {
		info.RedirectChain = append(info.RedirectChain, RedirectHop{
			FromURL:    targetURL,
			ToURL:      info.LocationHeader,
			StatusCode: resp.StatusCode,
		})

		// Follow the redirect chain (limit to 5 hops)
		currentURL := info.LocationHeader
		for i := 0; i < 5 && isRedirectStatus(info.FinalStatus); i++ {
			// Resolve relative URLs
			if !strings.HasPrefix(strings.ToLower(currentURL), "http") {
				base, parseErr := url.Parse(info.FinalURL)
				if parseErr == nil {
					rel, relErr := url.Parse(currentURL)
					if relErr == nil {
						currentURL = base.ResolveReference(rel).String()
					}
				}
			}

			nextReq, reqErr := http.NewRequestWithContext(context.Background(), "GET", currentURL, nil)
			if reqErr != nil {
				break
			}
			nextReq.Header.Set("User-Agent", v.userAgent)

			nextResp, respErr := noRedirectClient.Do(nextReq)
			if respErr != nil {
				break
			}

			nextBody, _ := io.ReadAll(io.LimitReader(nextResp.Body, v.maxBodySize))
			nextResp.Body.Close()

			info.FinalStatus = nextResp.StatusCode
			info.FinalURL = nextResp.Request.URL.String()
			info.Body = nextBody
			info.BodyHash = hashBody(nextBody)
			info.Headers = nextResp.Header.Clone()
			info.ContentType = nextResp.Header.Get("Content-Type")

			if strings.Contains(info.ContentType, "text/html") {
				info.Title = extractTitle(nextBody)
			}

			nextLocation := nextResp.Header.Get("Location")
			if isRedirectStatus(nextResp.StatusCode) && nextLocation != "" {
				info.RedirectChain = append(info.RedirectChain, RedirectHop{
					FromURL:    currentURL,
					ToURL:      nextLocation,
					StatusCode: nextResp.StatusCode,
				})
				currentURL = nextLocation
			} else {
				break
			}
		}

		info.RedirectCount = len(info.RedirectChain)
	}

	return info, nil
}

// classifyResponse analyzes the response and sets validation flags.
func (v *Validator) classifyResponse(resp *ResponseInfo, baseline *BaselineProfile) {
	// Handle obvious non-existent resources
	if resp.FinalStatus == 404 || resp.FinalStatus == 410 {
		resp.IsValidResource = false
		resp.ValidationNotes = append(resp.ValidationNotes, fmt.Sprintf("Explicit %d status", resp.FinalStatus))
		return
	}

	// Handle authentication/authorization
	if resp.FinalStatus == 401 {
		resp.IsAuthRequired = true
		resp.IsValidResource = true // Resource exists but requires auth
		resp.ValidationNotes = append(resp.ValidationNotes, "Authentication required (401)")
		return
	}

	if resp.FinalStatus == 403 {
		resp.IsAccessDenied = true
		resp.IsValidResource = true // Resource exists but access denied
		resp.ValidationNotes = append(resp.ValidationNotes, "Access denied (403)")
		return
	}

	// Handle server errors - resource may exist
	if resp.FinalStatus >= 500 {
		resp.IsValidResource = false
		resp.ValidationNotes = append(resp.ValidationNotes, fmt.Sprintf("Server error (%d)", resp.FinalStatus))
		return
	}

	// Detect redirect-to-login patterns
	if resp.IsRedirect {
		if isLoginRedirect(resp.FinalURL) {
			resp.IsAuthRequired = true
			resp.IsValidResource = true
			resp.ValidationNotes = append(resp.ValidationNotes, "Redirect to login/auth page")
			return
		}

		// Detect redirect-to-root
		if isRootRedirect(resp.FinalURL) {
			resp.IsSoft404 = true
			resp.IsValidResource = false
			resp.ValidationNotes = append(resp.ValidationNotes, "Redirects to root/home page")
			return
		}

		// If redirect leads to 404, original resource doesn't exist
		if resp.FinalStatus == 404 {
			resp.IsSoft404 = true
			resp.IsValidResource = false
			resp.ValidationNotes = append(resp.ValidationNotes, "Redirect chain ends in 404")
			return
		}
	}

	// For 2xx responses, perform deeper analysis
	if resp.FinalStatus >= 200 && resp.FinalStatus < 300 {
		// Check for soft-404 indicators in content
		if containsSoft404Indicators(string(resp.Body), resp.Title) {
			resp.IsSoft404 = true
			resp.IsValidResource = false
			resp.ValidationNotes = append(resp.ValidationNotes, "Soft-404: Content indicates not found")
			return
		}

		// Compare against baseline if available
		if baseline != nil {
			if isSimilarToBaseline(resp, baseline) {
				resp.IsSoft404 = true
				resp.IsSPACatchAll = true
				resp.IsValidResource = false
				resp.ValidationNotes = append(resp.ValidationNotes, "Response matches baseline (SPA catch-all or soft-404)")
				return
			}
		}

		// If we got here, treat as valid
		resp.IsValidResource = true
		resp.ValidationNotes = append(resp.ValidationNotes, fmt.Sprintf("Valid %d response", resp.FinalStatus))
	}
}

// isSimilarToBaseline checks if the response is similar to the baseline nonexistent page.
func isSimilarToBaseline(resp *ResponseInfo, baseline *BaselineProfile) bool {
	// Exact hash match
	if resp.BodyHash == baseline.BodyHash && baseline.BodyHash != "" {
		return true
	}

	// If baseline is a proper 404, don't compare against 200 responses
	if baseline.StatusCode == 404 && resp.FinalStatus == 200 {
		return false
	}

	// Status code and length match (both returning 200 with same content)
	if resp.FinalStatus == baseline.StatusCode &&
		resp.FinalStatus == 200 &&
		abs(len(resp.Body)-baseline.ContentLength) < 50 { // Tighter tolerance
		// Also check title similarity
		if resp.Title != "" && resp.Title == baseline.Title {
			return true
		}
	}

	// Very high structural similarity for normalized bodies (>95%)
	if baseline.NormalizedBody != "" && len(baseline.NormalizedBody) > 100 {
		normalizedResp := normalizeBody(resp.Body)
		similarity := stringSimilarity(normalizedResp, baseline.NormalizedBody)
		if similarity > 0.95 { // 95% similar for high confidence
			return true
		}
	}

	return false
}

// containsSoft404Indicators checks for common "not found" indicators.
func containsSoft404Indicators(body, title string) bool {
	titleLower := strings.ToLower(title)

	// Strong indicators in title (more reliable)
	titleIndicators := []string{
		"404",
		"not found",
		"page not found",
		"error 404",
		"not exist",
		"cannot find",
		"doesn't exist",
		"does not exist",
	}

	for _, indicator := range titleIndicators {
		if strings.Contains(titleLower, indicator) {
			// But be careful - a legitimate page about 404s would match
			// Check if the entire title is the indicator (not just contains it)
			titleWords := strings.Fields(titleLower)
			indicatorWords := strings.Fields(indicator)
			if len(titleWords) <= len(indicatorWords)+3 { // Allow small variations
				return true
			}
		}
	}

	// Body indicators (weaker, need context)
	// Look for patterns like <h1>404</h1> or prominent error messages
	patterns := []string{
		`<h1[^>]*>\s*(404|not\s+found|page\s+not\s+found)`,
		`<title[^>]*>\s*(404|not\s+found|page\s+not\s+found)\s*</title>`,
		`class=['"]error['"][^>]*>\s*(404|not\s+found|page\s+not\s+found)`,
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(`(?i)`+pattern, body); matched {
			return true
		}
	}

	// Framework-specific error pages
	frameworkPatterns := []string{
		"<h1>Server Error in '/' Application.</h1>",   // ASP.NET
		"Whitelabel Error Page",                       // Spring Boot
		"This localhost page can't be found",          // Chrome error
		"The page you were looking for doesn't exist", // Rails
	}

	for _, pattern := range frameworkPatterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}

	return false
}

// isLoginRedirect checks if a URL appears to be a login/auth page.
func isLoginRedirect(finalURL string) bool {
	loginPaths := []string{
		"/login",
		"/signin",
		"/sign-in",
		"/auth",
		"/authenticate",
		"/sso",
		"/oauth",
		"/account/login",
		"/user/login",
		"/users/sign_in",
	}

	parsed, err := url.Parse(finalURL)
	if err != nil {
		return false
	}

	path := strings.ToLower(strings.TrimRight(parsed.Path, "/"))
	for _, loginPath := range loginPaths {
		if path == loginPath || strings.HasSuffix(path, loginPath) {
			return true
		}
	}

	return false
}

// isRootRedirect checks if a URL redirects to the root/home page.
func isRootRedirect(finalURL string) bool {
	parsed, err := url.Parse(finalURL)
	if err != nil {
		return false
	}

	path := strings.Trim(parsed.Path, "/")

	// Common home page paths
	homePaths := []string{
		"",
		"index.html",
		"index.htm",
		"index.php",
		"home",
		"home.html",
		"default.html",
		"default.asp",
		"default.aspx",
	}

	for _, homePath := range homePaths {
		if path == homePath {
			return true
		}
	}

	return false
}

// isRedirectStatus checks if a status code is a redirect.
func isRedirectStatus(code int) bool {
	return code >= 300 && code < 400
}

// extractTitle extracts the <title> tag content from HTML.
func extractTitle(body []byte) string {
	bodyStr := string(body)
	lowerBody := strings.ToLower(bodyStr)

	idx := strings.Index(lowerBody, "<title")
	if idx == -1 {
		return ""
	}

	sub := bodyStr[idx:]
	startIdx := strings.Index(sub, ">")
	if startIdx == -1 {
		return ""
	}
	startIdx++

	endIdx := strings.Index(strings.ToLower(sub), "</title>")
	if endIdx == -1 || endIdx <= startIdx {
		return ""
	}

	title := sub[startIdx:endIdx]
	title = strings.TrimSpace(title)

	// Limit length
	if len(title) > 200 {
		title = title[:200]
	}

	return title
}

// normalizeBody removes dynamic content to enable consistent comparison.
// It strips timestamps, tokens, hashes, request IDs, analytics values,
// session cookies, and other volatile fields that change between requests.
func normalizeBody(body []byte) string {
	s := string(body)

	// Remove common dynamic values — order matters: more specific first
	patterns := []string{
		`__VIEWSTATE[^"]*"[^"]*"`,          // ASP.NET ViewState
		`__VIEWSTATEVALIDATOR[^"]*"[^"]*"`, // ASP.NET ViewState validator
		`csrf[_-]?token["\s:=]+[^"'\s<>]+`, // CSRF tokens
		`"timestamp":\s*\d+`,               // JSON timestamps
		`"requestId":\s*"[^"]+"`,           // Request IDs
		`"nonce":\s*"[^"]+"`,               // Nonces
		`"session_id":\s*"[^"]+"`,          // Session IDs
		`\d{10,}`,                          // Timestamps (Unix, nanoseconds)
		`[a-f0-9]{32,}`,                    // MD5/SHA hashes, tokens
		`[A-Za-z0-9+/]{40,}={0,2}`,         // Base64 blobs (JWT segments etc.)
		`\b\d{1,2}:\d{2}(:\d{2})?\b`,       // Time values (HH:MM or HH:MM:SS)
		`\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}`,  // ISO 8601 timestamps
	}

	normalized := s
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		normalized = re.ReplaceAllString(normalized, "NORMALIZED")
	}

	return normalized
}

// hashBody computes SHA-256 hash of body for fingerprinting.
func hashBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	hash := sha256.Sum256(body)
	return fmt.Sprintf("%x", hash)
}

// stringSimilarity computes a trigram-based similarity ratio between two strings.
// Returns a value between 0.0 (completely different) and 1.0 (identical).
// This is more robust than byte-level comparison for detecting SPA catch-alls
// where minor template differences exist.
func stringSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	// Work with normalized, truncated strings for performance
	const maxLen = 2000
	if len(a) > maxLen {
		a = a[:maxLen]
	}
	if len(b) > maxLen {
		b = b[:maxLen]
	}

	// Length similarity — heavy penalty for very different lengths
	lenDiff := abs(len(a) - len(b))
	maxLenVal := max(len(a), len(b))
	if maxLenVal == 0 {
		return 0.0
	}
	lenRatio := 1.0 - float64(lenDiff)/float64(maxLenVal)

	// Build trigram sets for both strings
	triA := trigrams(a)
	triB := trigrams(b)

	// Jaccard similarity on trigram sets
	if len(triA) == 0 || len(triB) == 0 {
		return lenRatio * 0.5
	}

	intersection := 0
	for t := range triA {
		if _, ok := triB[t]; ok {
			intersection++
		}
	}
	union := len(triA) + len(triB) - intersection
	trigramSim := float64(intersection) / float64(union)

	// Weighted combination: trigram similarity dominates, length ratio provides
	// a penalty when the content length difference is suspicious
	return trigramSim*0.7 + lenRatio*0.3
}

// trigrams extracts character trigrams from a string as a set.
func trigrams(s string) map[string]struct{} {
	tri := make(map[string]struct{})
	if len(s) < 3 {
		return tri
	}
	for i := 0; i <= len(s)-3; i++ {
		tri[s[i:i+3]] = struct{}{}
	}
	return tri
}

// abs returns absolute value of an integer.
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// max returns the maximum of two integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ShouldReportFinding determines if a validated response should generate a finding.
// This is the final gate: even if we probed something, we don't report it unless
// it's genuinely interesting.
func ShouldReportFinding(resp *ResponseInfo, isHighValue bool) bool {
	// Don't report clear non-existent resources
	if !resp.IsValidResource {
		return false
	}

	// Don't report soft-404s or SPA catch-alls
	if resp.IsSoft404 || resp.IsSPACatchAll {
		return false
	}

	// Auth-required and access-denied resources ARE interesting
	if resp.IsAuthRequired || resp.IsAccessDenied {
		return true
	}

	// For successful responses, only report if it's actually interesting
	// High-value paths (like .env, admin, etc.) should always be reported if accessible
	if isHighValue {
		return true
	}

	// Regular paths: only report if we got a clean 2xx response
	return resp.FinalStatus >= 200 && resp.FinalStatus < 300
}

// EvidenceSummary returns a human-readable summary of the validation state,
// suitable for inclusion in a Finding's Evidence field.
func EvidenceSummary(resp *ResponseInfo) string {
	if resp == nil {
		return "No validation performed"
	}

	var parts []string

	// Status summary
	if resp.OriginalStatus != resp.FinalStatus {
		parts = append(parts, fmt.Sprintf("Original: HTTP %d → Final: HTTP %d", resp.OriginalStatus, resp.FinalStatus))
	} else {
		parts = append(parts, fmt.Sprintf("HTTP %d", resp.FinalStatus))
	}

	// Redirect chain
	if len(resp.RedirectChain) > 0 {
		chain := ""
		for i, hop := range resp.RedirectChain {
			if i > 0 {
				chain += " → "
			}
			chain += fmt.Sprintf("%d→%s", hop.StatusCode, hop.ToURL)
		}
		parts = append(parts, "Chain: "+chain)
	}

	if resp.FinalURL != "" && resp.FinalURL != resp.RequestedURL {
		parts = append(parts, "Final URL: "+resp.FinalURL)
	}

	// Validation notes
	parts = append(parts, resp.ValidationNotes...)

	return strings.Join(parts, " | ")
}

// ValidationStateClass returns the appropriate ValidationState for a response.
func ValidationStateClass(resp *ResponseInfo, baselineAvailable bool) ValidationState {
	if resp == nil {
		return StateUnconfirmed
	}
	if resp.IsSoft404 || resp.IsSPACatchAll {
		return StateRejected
	}
	if !resp.IsValidResource {
		return StateRejected
	}

	// Auth/access-denied are confirmed — we know the resource exists
	if resp.IsAuthRequired || resp.IsAccessDenied {
		return StateConfirmed
	}

	// Redirects that lead to valid content
	if resp.IsRedirect && resp.FinalStatus >= 200 && resp.FinalStatus < 300 {
		if baselineAvailable {
			return StateConfirmed
		}
		return StateLikely
	}

	// Direct 2xx responses
	if resp.FinalStatus >= 200 && resp.FinalStatus < 300 {
		if baselineAvailable {
			return StateConfirmed
		}
		return StateLikely
	}

	return StatePossible
}

// RedirectSummary returns a human-readable redirect chain string.
func RedirectSummary(resp *ResponseInfo) []string {
	if resp == nil || len(resp.RedirectChain) == 0 {
		return nil
	}
	var chain []string
	for _, hop := range resp.RedirectChain {
		chain = append(chain, fmt.Sprintf("HTTP %d → %s", hop.StatusCode, hop.ToURL))
	}
	return chain
}
