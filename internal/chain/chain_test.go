package chain

import (
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-anansi-cli/internal/output"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		finding output.Finding
		want    []string
	}{
		{
			finding: output.Finding{
				Title:         "Exposed Environment File",
				Description:   ".env returned HTTP 200.",
				AffectedAsset: "https://host/.env",
			},
			want: []string{"info-disclosure"},
		},
		{
			finding: output.Finding{
				Title:       "Subdomain Takeover — GitHub Pages",
				Description: "Dangling CNAME to an unclaimed service.",
			},
			want: []string{"dns-misconfig"},
		},
		{
			finding: output.Finding{
				Title: "Drupal < 7.32 - Drupalgeddon SQL Injection (CVE-2014-3704)",
			},
			want: []string{"sql-injection", "dependency-vuln"},
		},
		{
			finding: output.Finding{
				Title: "WordPress < 6.4.3 - Unauthenticated Admin+ RCE (CVE-2024-31210)",
			},
			want: []string{"rce", "dependency-vuln"},
		},
		{
			finding: output.Finding{
				Title: "Missing HSTS",
			},
			want: []string{"crypto"},
		},
		{
			finding: output.Finding{
				Title:         "Exposed Admin Panel",
				AffectedAsset: "https://host/admin",
			},
			want: []string{"info-disclosure", "exposed-admin"},
		},
		{
			finding: output.Finding{
				Title:       "CORS Origin Reflection with Credentials",
				Description: "Server reflects arbitrary origin AND allows credentials.",
			},
			want: nil,
		},
		{
			finding: output.Finding{
				Title: "Unrelated Noise",
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		got := classify(tt.finding)
		for _, w := range tt.want {
			found := false
			for _, g := range got {
				if g == w {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("classify(%q) = %v, missing %q", tt.finding.Title, got, w)
			}
		}
	}
}

func TestRunAssemblesFullCompromiseChain(t *testing.T) {
	findings := []output.Finding{
		{Severity: output.Low, Title: "Exposed Environment File", AffectedAsset: "https://host/.env"},
		{Severity: output.Medium, Title: "Default Credentials Detected", AffectedAsset: "https://host"},
		{Severity: output.High, Title: "Access Bypass", AffectedAsset: "https://host"},
		{Severity: output.High, Title: "Privilege Escalation", AffectedAsset: "https://host"},
		{Severity: output.Critical, Title: "Unauthenticated RCE", AffectedAsset: "https://host"},
	}

	chains := Run(findings)
	if len(chains) == 0 {
		t.Fatal("Run returned no chains")
	}

	var found bool
	for _, c := range chains {
		if c.Name == "Full Compromise" {
			found = true
			if len(c.Steps) != 5 {
				t.Fatalf("Full Compromise chain has %d steps, want 5", len(c.Steps))
			}
			for i, s := range c.Steps {
				if s.Order != i+1 {
					t.Errorf("step %d has Order %d, want %d", i, s.Order, i+1)
				}
			}
			if c.Severity != output.Critical {
				t.Errorf("chain severity = %s, want CRITICAL", c.Severity)
			}
			if c.ID == "" {
				t.Error("chain ID not assigned")
			}
		}
	}
	if !found {
		t.Errorf("expected Full Compromise chain, got: %v", chainNames(chains))
	}
}

func TestRunGroupedByHost(t *testing.T) {
	// Two hosts with identical findings must produce independent chains.
	findings := []output.Finding{
		{Severity: output.Low, Title: "Exposed Environment File", AffectedAsset: "https://a.com/.env"},
		{Severity: output.Critical, Title: "Unauthenticated RCE", AffectedAsset: "https://a.com"},
		{Severity: output.Low, Title: "Exposed Environment File", AffectedAsset: "https://b.com/.env"},
		{Severity: output.Critical, Title: "Unauthenticated RCE", AffectedAsset: "https://b.com"},
	}

	chains := Run(findings)
	if len(chains) != 2 {
		t.Fatalf("Run returned %d chains, want 2 (one per host)", len(chains))
	}
	// Both chains should be the WebShell-adjacent / generic path; ensure the
	// assets referenced come from the two distinct hosts.
	assets := map[string]bool{}
	for _, c := range chains {
		for _, s := range c.Steps {
			assets[normalizeHost(s.AffectedAsset)] = true
		}
	}
	if !assets["a.com"] || !assets["b.com"] {
		t.Errorf("chains did not cover both hosts: %v", assets)
	}
}

func TestRunEmptyInput(t *testing.T) {
	if chains := Run(nil); chains != nil {
		t.Errorf("Run(nil) = %v, want nil", chains)
	}
	if chains := Run([]output.Finding{}); chains != nil {
		t.Errorf("Run(empty) = %v, want nil", chains)
	}
}

func TestRunNoChainForSingleClass(t *testing.T) {
	findings := []output.Finding{
		{Severity: output.High, Title: "Missing HSTS", AffectedAsset: "https://host"},
	}
	if chains := Run(findings); len(chains) != 0 {
		t.Errorf("single class should not chain, got %d chains", len(chains))
	}
}

func TestGenericEscalationOrderedBySeverity(t *testing.T) {
	findings := []output.Finding{
		{Severity: output.Critical, Title: "Remote Code Execution", AffectedAsset: "https://host"},
		{Severity: output.Low, Title: "Exposed Environment File", AffectedAsset: "https://host"},
	}
	chains := Run(findings)

	var generic *output.ExploitChain
	for i := range chains {
		if chains[i].Name == "Escalation Path" {
			generic = &chains[i]
			break
		}
	}
	if generic == nil {
		t.Fatalf("expected generic Escalation Path chain, got: %v", chainNames(chains))
	}
	if len(generic.Steps) != 2 {
		t.Fatalf("generic chain has %d steps, want 2", len(generic.Steps))
	}
	if generic.Steps[0].Severity != output.Low || generic.Steps[1].Severity != output.Critical {
		t.Errorf("steps not ordered low->critical: %s -> %s",
			generic.Steps[0].Severity, generic.Steps[1].Severity)
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"https://Host.COM/.env":     "host.com",
		"http://host.com":           "host.com",
		"https://www.host.com":      "host.com",
		"host.com:8443/admin":       "host.com",
		"https://a.b.host.io/x?y":   "a.b.host.io",
		"https://sub.host.com/api/": "sub.host.com",
	}
	for in, want := range tests {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestChainRanking(t *testing.T) {
	// A full five-step compromise should outrank a two-step path on the same host.
	findings := []output.Finding{
		{Severity: output.Low, Title: "Exposed Environment File", AffectedAsset: "https://host/.env"},
		{Severity: output.Medium, Title: "Default Credentials Detected", AffectedAsset: "https://host"},
		{Severity: output.High, Title: "Access Bypass", AffectedAsset: "https://host"},
		{Severity: output.High, Title: "Privilege Escalation", AffectedAsset: "https://host"},
		{Severity: output.Critical, Title: "Unauthenticated RCE", AffectedAsset: "https://host"},
	}
	chains := Run(findings)
	if len(chains) < 2 {
		t.Fatalf("expected multiple chains, got %d", len(chains))
	}
	if chains[0].Score < chains[1].Score {
		t.Errorf("chains not ranked by score: %d < %d", chains[0].Score, chains[1].Score)
	}
}

func TestPickBestPrefersConfirmed(t *testing.T) {
	confirmed := output.Finding{Severity: "MEDIUM", Title: "A", ValidationState: output.ValConfirmed}
	possible := output.Finding{Severity: "MEDIUM", Title: "B", ValidationState: output.ValPossible}

	best := pickBest([]output.Finding{possible, confirmed})
	if best.Title != "A" {
		t.Errorf("expected confirmed finding to be picked, got %q", best.Title)
	}
}

func TestValidationRank(t *testing.T) {
	tests := []struct {
		state output.ValidationState
		want  int
	}{
		{output.ValConfirmed, 4},
		{output.ValLikely, 3},
		{output.ValPossible, 2},
		{output.ValUnconfirmed, 1},
		{"", 0},
	}
	for _, tt := range tests {
		got := validationRank(tt.state)
		if got != tt.want {
			t.Errorf("validationRank(%q) = %d, want %d", tt.state, got, tt.want)
		}
	}
}

func chainNames(chains []output.ExploitChain) []string {
	names := make([]string, 0, len(chains))
	for _, c := range chains {
		var steps []string
		for _, s := range c.Steps {
			steps = append(steps, s.ClassID)
		}
		names = append(names, c.Name+"["+strings.Join(steps, ",")+"]")
	}
	return names
}
