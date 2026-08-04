package output

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestComputeRisk(t *testing.T) {
	tests := []struct {
		name   string
		counts map[string]int
		want   int
	}{
		{"no findings", map[string]int{Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0}, 0},
		{"one critical", map[string]int{Critical: 1, High: 0, Medium: 0, Low: 0, Info: 0}, 20},
		{"one high", map[string]int{Critical: 0, High: 1, Medium: 0, Low: 0, Info: 0}, 10},
		{"mixed", map[string]int{Critical: 2, High: 3, Medium: 1, Low: 2, Info: 0}, 79},
		{"cap at 100", map[string]int{Critical: 10, High: 0, Medium: 0, Low: 0, Info: 0}, 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeRisk(tt.counts)
			if got != tt.want {
				t.Errorf("computeRisk(%v) = %d, want %d", tt.counts, got, tt.want)
			}
		})
	}
}

func TestShortName(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"strict-transport-security", "HSTS"},
		{"content-security-policy", "CSP"},
		{"x-frame-options", "XFO"},
		{"x-content-type-options", "XCTO"},
		{"referrer-policy", "RP"},
		{"permissions-policy", "PP"},
		{"unknown-header", "unknown-header"},
	}
	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			got := shortName(tt.header)
			if got != tt.want {
				t.Errorf("shortName(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestRandomUA(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		ua := RandomUA()
		if ua == "" {
			t.Fatal("RandomUA returned empty string")
		}
		seen[ua] = true
	}
	if len(seen) < 2 {
		t.Fatal("RandomUA appears deterministic; expected variety")
	}
}

func TestJitterDelayNoStealth(t *testing.T) {
	d := JitterDelay(100, false)
	if d != 100*time.Millisecond {
		t.Fatalf("expected 100ms, got %v", d)
	}
}

func TestJitterDelayZero(t *testing.T) {
	d := JitterDelay(0, true)
	if d != 0 {
		t.Fatalf("expected 0, got %v", d)
	}
}

func TestDefaultUA(t *testing.T) {
	if DefaultUA == "" {
		t.Fatal("DefaultUA should not be empty")
	}
}

func TestReportJSONIncludesTechResults(t *testing.T) {
	report := &Report{
		Target: "example.com",
		TechResults: []TechResult{
			{
				URL:        "https://example.com",
				Stack:      "WordPress",
				Version:    "6.0.2",
				DetectedBy: "generator meta tag",
				Components: []string{"plugin:elementor@3.10.0"},
				Findings: []Finding{
					{Severity: Critical, Title: "Test Finding", AffectedAsset: "https://example.com"},
				},
			},
		},
	}
	var buf bytes.Buffer
	old := json.NewEncoder(&buf)
	if err := old.Encode(report); err != nil {
		t.Fatalf("encoding report: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "TechResults") || !strings.Contains(out, "WordPress") || !strings.Contains(out, "6.0.2") {
		t.Fatalf("JSON output missing tech results: %s", out)
	}
}

func TestTechTableRenders(_ *testing.T) {
	r := New("terminal", false)
	r.TechTable([]TechResult{
		{
			URL:        "https://example.com",
			Stack:      "WordPress",
			Version:    "6.0.2",
			DetectedBy: "generator meta tag",
			Components: []string{"plugin:elementor@3.10.0"},
			Findings: []Finding{
				{Severity: High, Title: "Outdated", AffectedAsset: "https://example.com", Remediation: "upgrade"},
			},
		},
	})
	r.TechTable(nil)
}

func TestChainTableRenders(_ *testing.T) {
	r := New("terminal", false)
	r.ChainTable([]ExploitChain{
		{
			ID:       "chain-1",
			Name:     "Full Compromise",
			Summary:  "Escalation to full control.",
			Severity: Critical,
			Score:    57,
			Steps: []ChainStep{
				{Order: 1, Class: "Sensitive Information Disclosure", ClassID: "info-disclosure", Severity: Low, FindingTitle: "Exposed Environment File", AffectedAsset: "https://host/.env", Technique: "Harvest secrets."},
				{Order: 2, Class: "Remote Code Execution", ClassID: "rce", Severity: Critical, FindingTitle: "Unauthenticated RCE", AffectedAsset: "https://host", Technique: "Execute code."},
			},
		},
	})
	r.ChainTable(nil)
}

func TestSummaryIncludesChains(_ *testing.T) {
	r := New("terminal", false)
	report := &Report{
		Target:    "example.com",
		StartedAt: time.Now(),
		Chains: []ExploitChain{
			{Name: "Full Compromise", Severity: Critical, Score: 57, Steps: []ChainStep{{Order: 1, ClassID: "rce"}}},
		},
	}
	r.Summary(report)
}

func TestMarkdownRendersChains(t *testing.T) {
	r := New("markdown", false)
	report := &Report{
		Target:    "example.com",
		StartedAt: time.Now(),
		Chains: []ExploitChain{
			{
				Name:     "Full Compromise",
				Summary:  "Escalation to full control.",
				Severity: Critical,
				Steps: []ChainStep{
					{Order: 1, Class: "Sensitive Information Disclosure", ClassID: "info-disclosure", Severity: Low, FindingTitle: "Exposed Environment File", AffectedAsset: "https://host/.env", Technique: "Harvest secrets."},
				},
			},
		},
	}
	out := captureStdout(t, func() { r.Summary(report) })
	if !strings.Contains(out, "## Exploit Chains") {
		t.Fatalf("markdown output missing Exploit Chains section:\n%s", out)
	}
	if !strings.Contains(out, "Full Compromise") {
		t.Fatalf("markdown output missing chain name:\n%s", out)
	}
}

func TestHTMLRendersChains(t *testing.T) {
	r := New("html", false)
	report := &Report{
		Target:    "example.com",
		StartedAt: time.Now(),
		Chains: []ExploitChain{
			{
				Name:     "Full Compromise",
				Summary:  "Escalation to full control.",
				Severity: Critical,
				Steps: []ChainStep{
					{Order: 1, Class: "Remote Code Execution", ClassID: "rce", Severity: Critical, FindingTitle: "Unauthenticated RCE", AffectedAsset: "https://host", Technique: "Execute code."},
				},
			},
		},
	}
	out := captureStdout(t, func() { r.Summary(report) })
	if !strings.Contains(out, "Exploit Chains") {
		t.Fatalf("HTML output missing Exploit Chains card:\n%s", out)
	}
	if !strings.Contains(out, "Full Compromise") {
		t.Fatalf("HTML output missing chain name:\n%s", out)
	}
}

// captureStdout runs fn while os.Stdout points at a temporary file and returns
// everything written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "anansi-out-*.txt")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}

	old := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = old }()
	defer func() { _ = f.Close() }()

	fn()

	if err := f.Sync(); err != nil {
		t.Fatalf("syncing temp file: %v", err)
	}
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("reading temp file: %v", err)
	}
	return string(data)
}

func TestReportJSONIncludesChains(t *testing.T) {
	report := &Report{
		Target: "example.com",
		Chains: []ExploitChain{
			{
				ID:       "chain-1",
				Name:     "Full Compromise",
				Severity: Critical,
				Steps: []ChainStep{
					{Order: 1, ClassID: "rce", Class: "Remote Code Execution", FindingTitle: "Unauthenticated RCE"},
				},
			},
		},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(report); err != nil {
		t.Fatalf("encoding report: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Chains") || !strings.Contains(out, "Full Compromise") || !strings.Contains(out, "Unauthenticated RCE") {
		t.Fatalf("JSON output missing chains: %s", out)
	}
}

func TestProgressSuppressedWhenNotTTY(t *testing.T) {
	out := captureStdout(t, func() {
		r := &Renderer{format: "terminal", tty: false}
		r.Progress(5, 10, "Test")
	})
	if strings.Contains(out, "\r") || strings.Contains(out, "%") {
		t.Errorf("progress frame written to non-tty output: %q", out)
	}
}

func TestProgressRendersOnTTY(t *testing.T) {
	out := captureStdout(t, func() {
		r := &Renderer{format: "terminal", tty: true}
		r.Progress(10, 10, "Test")
	})
	if !strings.Contains(out, "100%") || !strings.Contains(out, "Test") {
		t.Errorf("tty progress frame not rendered: %q", out)
	}
}
