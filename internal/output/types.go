// Package output defines shared data types used across all scan modules and renders
// the final report in multiple formats (terminal, JSON, Markdown, HTML).
package output

import (
	"math/rand"
	"time"
)

// Severity levels used to classify findings across all scan modules.
const (
	Critical = "CRITICAL"
	High     = "HIGH"
	Medium   = "MEDIUM"
	Low      = "LOW"
	Info     = "INFO"
)

// Source type constants identify how a subdomain was discovered.
const (
	SourceCrtSh    = "crtsh"
	SourceWordlist = "wordlist"
	SourceSAN      = "san"
	SourceMutation = "mutation"
)

// CompanyName is the organisation behind this tool.
const CompanyName = "QYVORA OffSec"

// CompanyURL is the Netlify-hosted landing page (no custom domain yet).
const CompanyURL = "https://qyvora.netlify.app"

// BuiltIn is the origin location of this project.
const BuiltIn = "Tamale, Ghana"

// Finding represents a single vulnerability or notable observation discovered
// during any scan phase. Each finding carries a severity, a human-readable
// title, the affected asset, evidence, and a remediation suggestion.
type Finding struct {
	Severity      string
	Title         string
	AffectedAsset string
	Description   string
	Evidence      string
	Remediation   string
}

// OSINTResult holds a single piece of open-source intelligence discovered
// about the target organisation: emails, phone numbers, employee names,
// social media handles, or organisational metadata.
type OSINTResult struct {
	Category string // "email", "phone", "employee", "org"
	Value    string
	Source   string // e.g. WHOIS, page URL, certificate
	Context  string // surrounding text or label
}

// Report is the full scan result object. It is populated incrementally by each
// scan phase and rendered at the end in the chosen output format.
type Report struct {
	Target        string
	StartedAt     time.Time
	Duration      time.Duration
	Subdomains    []SubdomainResult
	ProbeResults  []ProbeResult
	TLSResults    []TLSResult
	HeaderResults []HeaderResult
	Findings      []Finding
	OSINTResults  []OSINTResult
	TechResults   []TechResult
}

// SubdomainResult holds the outcome of a single subdomain resolution attempt.
// Source indicates how it was found (crt.sh, wordlist, SAN, mutation).
type SubdomainResult struct {
	FQDN       string
	IPs        []string
	Source     string
	Resolved   bool
	DeadCNAMEs []string
}

// ProbeResult captures metadata from an HTTP/HTTPS probe of a single host,
// including response status, headers, page title, detected technologies,
// and timing information.
type ProbeResult struct {
	FQDN           string
	URL            string
	FinalURL       string
	StatusCode     int
	Server         string
	TechHeaders    map[string]string
	Technologies   []string
	Title          string
	ResponseTimeMs int64
	IsAlive        bool
	RedirectChain  []string
}

// TLSResult contains certificate and protocol information gathered during
// a TLS handshake with a target host, along with any derived findings.
type TLSResult struct {
	Hostname        string
	Protocol        string
	Cipher          string
	Issuer          string
	Subject         string
	ValidFrom       string
	ValidTo         string
	DaysUntilExpiry int
	Expired         bool
	ExpiringSoon    bool
	SelfSigned      bool
	SANs            []string
	Findings        []Finding
	Supported       bool
	Error           string
}

// HeaderResult records the presence or absence of security-related HTTP
// response headers for a single URL, together with CORS configuration
// details and any associated findings.
type HeaderResult struct {
	URL      string
	Headers  map[string]string
	CORS     string
	Findings []Finding
	Success  bool
	Error    string
}

// TechResult records the detected application stack for a single URL: the
// identified platform, its version (when discoverable), how the version was
// identified, detected components (e.g. WordPress plugins), and any
// version-specific or misconfiguration findings derived from the deep audit.
type TechResult struct {
	URL        string
	Stack      string
	Version    string
	DetectedBy string
	Components []string
	Findings   []Finding
}

// randomUserAgents is a pool of realistic User-Agent strings used when
// stealth mode is active. Rotating through these helps evade basic
// bot-detection mechanisms.
var randomUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
}

// RandomUA returns a random User-Agent string from the built-in pool.
func RandomUA() string {
	return randomUserAgents[rand.Intn(len(randomUserAgents))]
}

// DefaultUA is used when stealth mode is off.
const DefaultUA = "Mozilla/5.0 (compatible; ANANSI-CLI/1.0)"

// JitterDelay returns delayMs plus a random jitter of ±50 % when stealth
// is enabled; otherwise it returns the base delay unchanged.
func JitterDelay(delayMs int, stealth bool) time.Duration {
	if delayMs <= 0 {
		return 0
	}
	base := time.Duration(delayMs) * time.Millisecond
	if !stealth {
		return base
	}
	jitter := time.Duration(rand.Intn(delayMs)) * time.Millisecond
	if rand.Intn(2) == 0 {
		return base + jitter
	}
	return base - jitter
}

