package output

import (
	"bytes"
	"encoding/json"
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

