// Package output defines shared data types used across all scan modules and renders
// the final report in multiple formats (terminal, JSON, Markdown, HTML).
package output

import (
	"math/rand"
	"time"

	"github.com/QYVORA/qyvora-anansi/internal/validation"
	"github.com/QYVORA/qyvora-anansi/internal/version"
)

// Severity levels used to classify findings across all scan modules.
const (
	Critical = "CRITICAL"
	High     = "HIGH"
	Medium   = "MEDIUM"
	Low      = "LOW"
	Info     = "INFO"
)

// Confidence levels describe how strong the evidence is that a finding is real.
// This is independent of severity: a high-severity finding may have low
// confidence when based only on version banners.
const (
	Confirmed         = "CONFIRMED"     // direct evidence, validated, reproducible
	ConfHigh          = "HIGH"          // strong indicators, multiple signals
	ConfMedium        = "MEDIUM"        // moderate evidence, some signals
	ConfLow           = "LOW"           // weak evidence, single signal (version banners, headers)
	ConfInformational = "INFORMATIONAL" // observation only, no security implication
)

// Source type constants identify how a subdomain was discovered.
const (
	SourceCrtSh    = "crtsh"
	SourceWordlist = "wordlist"
	SourceSAN      = "san"
	SourceMutation = "mutation"
)

// CompanyName is the organisation behind this tool.
const CompanyName = version.CompanyName

// CompanyURL is the Netlify-hosted landing page (no custom domain yet).
const CompanyURL = version.CompanyURL

// CompanyEmail is the public security contact for the QYVORA organisation.
const CompanyEmail = version.CompanyEmail

// BuiltIn is the origin location of this project.
const BuiltIn = version.CompanyCity

// ValidationState is re-exported from the validation package for convenience.
// It describes the confidence level of a finding based on response validation.
type ValidationState = validation.ValidationState

// Re-export validation state constants for use in output modules.
const (
	ValConfirmed   = validation.StateConfirmed
	ValLikely      = validation.StateLikely
	ValPossible    = validation.StatePossible
	ValUnconfirmed = validation.StateUnconfirmed
	ValRejected    = validation.StateRejected
)

// Finding represents a single vulnerability or notable observation discovered
// during any scan phase. Each finding carries a severity, a human-readable
// title, the affected asset, evidence, and a remediation suggestion.
//
// ID is a stable per-scan identifier (assigned after deduplication) that the
// PoC/exploitation layer uses to correlate findings with exploit results.
// Status tracks the finding through the shared QYVORA lifecycle when it is
// selected for validation/exploitation (suspected -> validated -> exploitable
// -> exploited -> evidence_captured), and is empty when it was never selected.
//
// ValidationState records the outcome of the response-validation pipeline:
// DISCOVERY ≠ VALIDATED FINDING. A raw HTTP 200 is not sufficient to
// confirm a resource exists.
type Finding struct {
	Severity      string `json:"severity"`
	Confidence    string `json:"confidence"`
	Title         string `json:"title"`
	AffectedAsset string `json:"affected_asset"`
	Description   string `json:"description,omitempty"`
	Evidence      string `json:"evidence,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ID            string `json:"id,omitempty"`
	Status        string `json:"status,omitempty"`

	// Validation fields — the detection-quality pipeline
	ValidationState ValidationState `json:"validation_state,omitempty"`
	FinalURL        string          `json:"final_url,omitempty"`       // URL after redirects, if different from AffectedAsset
	OriginalStatus  int             `json:"original_status,omitempty"` // HTTP status before redirect chain
	FinalStatus     int             `json:"final_status,omitempty"`    // HTTP status after redirect chain
	RedirectChain   []string        `json:"redirect_chain,omitempty"`  // Human-readable redirect hops
}

// OSINTResult holds a single piece of open-source intelligence discovered
// about the target organisation: emails, phone numbers, employee names,
// social media handles, or organisational metadata.
type OSINTResult struct {
	Category string `json:"category"` // "email", "phone", "employee", "org"
	Value    string `json:"value"`
	Source   string `json:"source"`  // e.g. WHOIS, page URL, certificate
	Context  string `json:"context"` // surrounding text or label
}

// ChainStep is one vulnerability class inside an exploit chain.  It records
// which real finding triggered the step (title, severity, asset) and the
// exploitation technique recommended for that class.
type ChainStep struct {
	Order           int    `json:"order"`         // 1-based position in the chain
	Class           string `json:"class"`         // vulnerability class name, e.g. "SQL Injection"
	ClassID         string `json:"class_id"`      // short class identifier, e.g. "sql-injection"
	Severity        string `json:"severity"`      // severity of the step (worst matching finding)
	FindingTitle    string `json:"finding_title"` // title of the finding that triggered this step
	FindingSeverity string `json:"finding_severity"`
	AffectedAsset   string `json:"affected_asset"`
	Technique       string `json:"technique"` // exploitation technique for this class
}

// ExploitChain is an ordered sequence of vulnerability classes that, taken
// together, describe a realistic attack path from low-severity foothold to
// full compromise.  Chains are assembled from the scan's real findings and
// ranked by severity, length, and score.
type ExploitChain struct {
	ID       string      `json:"id"`       // stable identifier: "chain-<n>"
	Name     string      `json:"name"`     // narrative name, e.g. "Full Compromise"
	Summary  string      `json:"summary"`  // human-readable description of the kill path
	Severity string      `json:"severity"` // worst step severity in the chain
	Score    int         `json:"score"`    // ranking score
	Steps    []ChainStep `json:"steps"`
}

// ExploitResult is the machine-readable outcome of one PoC/exploitation run
// against one finding. It intentionally mirrors the exploit package's Result
// shape without importing it, keeping the output package free of package
// cycles. Evidence is stored as a list of non-sensitive summaries.
type ExploitResult struct {
	ExploitID     string    `json:"exploit_id,omitempty"`
	ModuleID      string    `json:"module_id,omitempty"`
	ModuleName    string    `json:"module_name,omitempty"`
	Target        string    `json:"target"`
	FindingID     string    `json:"finding_id,omitempty"`
	FindingTitle  string    `json:"finding_title,omitempty"`
	Vulnerability string    `json:"vulnerability,omitempty"`
	Status        string    `json:"status"`
	Risk          string    `json:"risk"`
	DryRun        bool      `json:"dry_run"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	Evidence      []string  `json:"evidence,omitempty"`
	Error         string    `json:"error,omitempty"`
	CleanupStatus string    `json:"cleanup_status,omitempty"`
}

// Report is the full scan result object. It is populated incrementally by each
// scan phase and rendered at the end in the chosen output format.
type Report struct {
	Target         string            `json:"target"`
	StartedAt      time.Time         `json:"started_at"`
	Duration       time.Duration     `json:"duration_ns"`
	Subdomains     []SubdomainResult `json:"subdomains,omitempty"`
	ProbeResults   []ProbeResult     `json:"probes,omitempty"`
	TLSResults     []TLSResult       `json:"tls,omitempty"`
	HeaderResults  []HeaderResult    `json:"headers,omitempty"`
	Findings       []Finding         `json:"findings,omitempty"`
	OSINTResults   []OSINTResult     `json:"osint,omitempty"`
	TechResults    []TechResult      `json:"technology,omitempty"`
	Chains         []ExploitChain    `json:"chains,omitempty"`
	ExploitResults []ExploitResult   `json:"exploits,omitempty"`
}

// SubdomainResult holds the outcome of a single subdomain resolution attempt.
// Source indicates how it was found (crt.sh, wordlist, SAN, mutation).
type SubdomainResult struct {
	FQDN       string   `json:"fqdn"`
	IPs        []string `json:"ips,omitempty"`
	Source     string   `json:"source"`
	Resolved   bool     `json:"resolved"`
	DeadCNAMEs []string `json:"dead_cnames,omitempty"`
}

// ProbeResult captures metadata from an HTTP/HTTPS probe of a single host,
// including response status, headers, page title, detected technologies,
// and timing information.
type ProbeResult struct {
	FQDN           string            `json:"fqdn"`
	URL            string            `json:"url"`
	FinalURL       string            `json:"final_url,omitempty"`
	StatusCode     int               `json:"status_code"`
	Server         string            `json:"server,omitempty"`
	TechHeaders    map[string]string `json:"tech_headers,omitempty"`
	Technologies   []string          `json:"technologies,omitempty"`
	Title          string            `json:"title,omitempty"`
	ResponseTimeMs int64             `json:"response_time_ms"`
	IsAlive        bool              `json:"is_alive"`
	RedirectChain  []string          `json:"redirect_chain,omitempty"`
}

// TLSResult contains certificate and protocol information gathered during
// a TLS handshake with a target host, along with any derived findings.
type TLSResult struct {
	Hostname        string    `json:"hostname"`
	Protocol        string    `json:"protocol,omitempty"`
	Cipher          string    `json:"cipher,omitempty"`
	Issuer          string    `json:"issuer,omitempty"`
	Subject         string    `json:"subject,omitempty"`
	ValidFrom       string    `json:"valid_from,omitempty"`
	ValidTo         string    `json:"valid_to,omitempty"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
	Expired         bool      `json:"expired"`
	ExpiringSoon    bool      `json:"expiring_soon"`
	SelfSigned      bool      `json:"self_signed"`
	SANs            []string  `json:"sans,omitempty"`
	Findings        []Finding `json:"findings,omitempty"`
	Supported       bool      `json:"supported"`
	Error           string    `json:"error,omitempty"`
}

// HeaderResult records the presence or absence of security-related HTTP
// response headers for a single URL, together with CORS configuration
// details and any associated findings.
type HeaderResult struct {
	URL      string            `json:"url"`
	Headers  map[string]string `json:"headers,omitempty"`
	CORS     string            `json:"cors,omitempty"`
	Findings []Finding         `json:"findings,omitempty"`
	Success  bool              `json:"success"`
	Error    string            `json:"error,omitempty"`
}

// TechResult records the detected application stack for a single URL: the
// identified platform, its version (when discoverable), how the version was
// identified, detected components (e.g. WordPress plugins), and any
// version-specific or misconfiguration findings derived from the deep audit.
type TechResult struct {
	URL        string    `json:"url"`
	Stack      string    `json:"stack,omitempty"`
	Version    string    `json:"version,omitempty"`
	DetectedBy string    `json:"detected_by,omitempty"`
	Components []string  `json:"components,omitempty"`
	Findings   []Finding `json:"findings,omitempty"`
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
