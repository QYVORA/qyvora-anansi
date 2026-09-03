package discovery

import (
	"testing"

	"github.com/QYVORA/qyvora-anansi/internal/output"
)

func TestMutateSubdomains(t *testing.T) {
	tests := []struct {
		name     string
		resolved []string
		target   string
		wantMin  int
	}{
		{
			name:     "empty input",
			resolved: nil,
			target:   "example.com",
			wantMin:  0,
		},
		{
			name:     "only apex domain",
			resolved: []string{"example.com"},
			target:   "example.com",
			wantMin:  0,
		},
		{
			name:     "single prefix generates hyphenations",
			resolved: []string{"api.example.com"},
			target:   "example.com",
			wantMin:  10,
		},
		{
			name:     "numeric prefix also generates increments",
			resolved: []string{"web01.example.com", "api.example.com"},
			target:   "example.com",
			wantMin:  20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MutateSubdomains(tt.resolved, tt.target)
			if tt.wantMin == 0 && got != nil {
				t.Fatalf("expected nil, got %d mutations", len(got))
			}
			if tt.wantMin == 0 {
				return
			}
			if len(got) < tt.wantMin {
				t.Fatalf("expected at least %d mutations, got %d: %v", tt.wantMin, len(got), got)
			}
		})
	}
}

func TestMutateSubdomainsNoDuplicates(t *testing.T) {
	got := MutateSubdomains([]string{"api.example.com", "dev.example.com"}, "example.com")
	seen := map[string]bool{}
	for _, m := range got {
		if seen[m] {
			t.Fatalf("duplicate mutation: %s", m)
		}
		seen[m] = true
	}
}

func TestMutateSubdomainsAllSuffix(t *testing.T) {
	got := MutateSubdomains([]string{"api.example.com"}, "example.com")
	for _, m := range got {
		if len(m) < 12 || m[len(m)-12:] != ".example.com" {
			t.Fatalf("mutation %q does not end with .example.com", m)
		}
	}
}

func TestLiveHosts(t *testing.T) {
	results := []output.SubdomainResult{
		{FQDN: "live.example.com", Resolved: true, IPs: []string{"1.2.3.4"}},
		{FQDN: "dead.example.com", Resolved: false},
		{FQDN: "also-live.example.com", Resolved: true, IPs: []string{"5.6.7.8"}},
	}
	live := LiveHosts(results)
	if len(live) != 2 {
		t.Fatalf("expected 2 live hosts, got %d: %v", len(live), live)
	}
	if live[0] != "live.example.com" || live[1] != "also-live.example.com" {
		t.Fatalf("unexpected live hosts: %v", live)
	}
}

func TestIsWildcardResult(t *testing.T) {
	t.Run("all wildcard", func(t *testing.T) {
		m := map[string]struct{}{"1.2.3.4": {}}
		if !isWildcardResult([]string{"1.2.3.4"}, m) {
			t.Error("expected true")
		}
	})
	t.Run("mixed", func(t *testing.T) {
		m := map[string]struct{}{"1.2.3.4": {}}
		if isWildcardResult([]string{"1.2.3.4", "5.6.7.8"}, m) {
			t.Error("expected false")
		}
	})
	t.Run("no wildcard", func(t *testing.T) {
		m := map[string]struct{}{"1.2.3.4": {}}
		if isWildcardResult([]string{"5.6.7.8"}, m) {
			t.Error("expected false")
		}
	})
	t.Run("empty ips", func(t *testing.T) {
		m := map[string]struct{}{"1.2.3.4": {}}
		if isWildcardResult(nil, m) {
			t.Error("expected false")
		}
	})
	t.Run("empty map", func(t *testing.T) {
		if isWildcardResult([]string{"1.2.3.4"}, map[string]struct{}{}) {
			t.Error("expected false")
		}
	})
}
