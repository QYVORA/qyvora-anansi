package assets

import (
	"strings"
	"testing"
)

func TestLoadData(t *testing.T) {
	// Test that embedded wordlists load
	tests := []struct {
		path     string
		minLines int
	}{
		{"wordlists/subdomains/default.txt", 1},
		{"wordlists/subdomains/deep.txt", 1},
		{"wordlists/paths/default.txt", 1},
		{"wordlists/headers/rules.txt", 1},
		{"wordlists/takeover/fingerprints.txt", 1},
		{"wordlists/probe/tech_headers.txt", 1},
		{"wordlists/tech/fingerprints.txt", 100},
		{"wordlists/tech/vulns.txt", 40},
		{"wordlists/tech/wordpress.txt", 1},
		{"wordlists/tech/drupal.txt", 1},
		{"wordlists/tech/joomla.txt", 1},
		{"wordlists/tech/generic.txt", 20},
		{"wordlists/tech/magento.txt", 1},
		{"wordlists/tech/ghost.txt", 1},
		{"wordlists/tech/moodle.txt", 1},
		{"wordlists/tech/mediawiki.txt", 1},
		{"wordlists/tech/laravel.txt", 1},
		{"wordlists/chain/classes.txt", 30},
		{"wordlists/chain/chains.txt", 5},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			lines := LoadData(tt.path)
			if len(lines) < tt.minLines {
				t.Errorf("LoadData(%q) returned %d lines, want at least %d", tt.path, len(lines), tt.minLines)
			}
		})
	}
}

func TestLoadDataSkipsCommentsAndBlanks(t *testing.T) {
	lines := LoadData("wordlists/headers/rules.txt")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			t.Errorf("LoadData returned comment line: %q", line)
		}
		if strings.TrimSpace(line) == "" {
			t.Errorf("LoadData returned blank line")
		}
	}
}

func TestLoadWordlistDefault(t *testing.T) {
	words := LoadWordlist("", false)
	if len(words) == 0 {
		t.Fatal("LoadWordlist returned empty default wordlist")
	}
}

func TestLoadWordlistCustom(t *testing.T) {
	words := LoadWordlist("/nonexistent/path.txt", false)
	if words != nil {
		t.Fatal("LoadWordlist for nonexistent path should return nil")
	}
}

func TestLoadWordlistDeep(t *testing.T) {
	shallow := LoadWordlist("", false)
	deep := LoadWordlist("", true)
	if len(deep) <= len(shallow) {
		t.Fatal("deep wordlist should be larger than default")
	}
}

func TestTechVulnsDataIntegrity(t *testing.T) {
	// Format: <stack>|<target>|<title>|<severity>|<minVersion>|<maxVersion>|<description>|<remediation>
	validSeverities := map[string]bool{"INFO": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
	for _, line := range LoadData("wordlists/tech/vulns.txt") {
		parts := strings.Split(line, "|")
		if len(parts) < 4 {
			t.Errorf("vulns.txt malformed line (want >=4 fields, got %d): %q", len(parts), line)
			continue
		}
		if parts[0] == "" || parts[2] == "" {
			t.Errorf("vulns.txt line missing stack/title: %q", line)
		}
		if !validSeverities[parts[3]] {
			t.Errorf("vulns.txt invalid severity %q in %q", parts[3], line)
		}
	}
}

func TestTechStackDataIntegrity(t *testing.T) {
	// Each <stack>.txt must use the audit format and only reference a stack
	// name that exists in fingerprints.txt.  Column count varies: 4 columns
	// (path|title|severity|bodyMatch) or 5 (adds locationMatch).
	validSeverities := map[string]bool{"INFO": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}

	knownStacks := map[string]bool{}
	for _, line := range LoadData("wordlists/tech/fingerprints.txt") {
		parts := strings.Split(line, "|")
		if len(parts) < 2 || parts[0] == "" {
			t.Errorf("fingerprints.txt malformed line: %q", line)
			continue
		}
		knownStacks[strings.TrimSpace(parts[0])] = true
	}
	if len(knownStacks) == 0 {
		t.Fatal("fingerprints.txt produced no stack names")
	}

	stacks := []string{"wordpress", "drupal", "joomla", "magento", "ghost", "moodle", "mediawiki", "laravel", "generic"}
	for _, stack := range stacks {
		t.Run(stack, func(t *testing.T) {
			for _, line := range LoadData("wordlists/tech/" + stack + ".txt") {
				parts := strings.Split(line, "|")
				if len(parts) < 4 || len(parts) > 5 {
					t.Errorf("%s.txt malformed line (want 4-5 fields, got %d): %q", stack, len(parts), line)
					continue
				}
				if parts[0] == "" || parts[1] == "" {
					t.Errorf("%s.txt line missing path/title: %q", stack, line)
				}
				if !validSeverities[parts[2]] {
					t.Errorf("%s.txt invalid severity %q in %q", stack, parts[2], line)
				}
			}
		})
	}
}

func TestTechFingerprintsNonEmptyNeedles(t *testing.T) {
	for _, line := range LoadData("wordlists/tech/fingerprints.txt") {
		parts := strings.Split(line, "|")
		if len(parts) != 2 {
			t.Errorf("fingerprints.txt malformed line: %q", line)
			continue
		}
		if strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			t.Errorf("fingerprints.txt has empty stack or needle: %q", line)
		}
	}
}

func TestTakeoverFingerprintsDataIntegrity(t *testing.T) {
	for _, line := range LoadData("wordlists/takeover/fingerprints.txt") {
		parts := strings.Split(line, "|")
		if len(parts) != 3 {
			t.Errorf("takeover/fingerprints.txt malformed line: %q", line)
			continue
		}
		if parts[0] == "" || parts[1] == "" || parts[2] == "" {
			t.Errorf("takeover/fingerprints.txt has empty field: %q", line)
		}
	}
}

func TestHeadersRulesDataIntegrity(t *testing.T) {
	for _, line := range LoadData("wordlists/headers/rules.txt") {
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			t.Errorf("headers/rules.txt malformed line (want >=3 fields): %q", line)
		}
	}
}

func TestChainClassesDataIntegrity(t *testing.T) {
	// Format: <class-id>|<class name>|<keyword1,keyword2,...>|<technique>
	// The engine expects exactly 30 classes covering the standard vulnerability
	// taxonomy used for exploit-chain assembly.
	classes := LoadData("wordlists/chain/classes.txt")
	if len(classes) != 30 {
		t.Fatalf("chain/classes.txt has %d classes, want exactly 30", len(classes))
	}

	seen := map[string]bool{}
	for _, line := range classes {
		parts := strings.Split(line, "|")
		if len(parts) != 4 {
			t.Errorf("chain/classes.txt malformed line (want 4 fields, got %d): %q", len(parts), line)
			continue
		}
		if parts[0] == "" || parts[1] == "" || parts[3] == "" {
			t.Errorf("chain/classes.txt has an empty class-id/name/technique: %q", line)
		}
		if seen[parts[0]] {
			t.Errorf("chain/classes.txt duplicate class id %q", parts[0])
		}
		seen[parts[0]] = true

		keywords := strings.Split(parts[2], ",")
		if len(keywords) == 0 {
			t.Errorf("chain/classes.txt class %q has no keywords", parts[0])
		}
		for _, kw := range keywords {
			if strings.TrimSpace(kw) == "" {
				t.Errorf("chain/classes.txt class %q has an empty keyword", parts[0])
			}
		}
	}
}

func TestChainTemplatesReferenceKnownClasses(t *testing.T) {
	// Format: <chain name>|<step1,step2,...>|<summary>
	// Every step must reference a class id defined in classes.txt.
	known := map[string]bool{}
	for _, line := range LoadData("wordlists/chain/classes.txt") {
		parts := strings.Split(line, "|")
		if len(parts) >= 1 && parts[0] != "" {
			known[parts[0]] = true
		}
	}

	for _, line := range LoadData("wordlists/chain/chains.txt") {
		parts := strings.Split(line, "|")
		if len(parts) != 3 {
			t.Errorf("chain/chains.txt malformed line (want 3 fields, got %d): %q", len(parts), line)
			continue
		}
		if parts[0] == "" || parts[2] == "" {
			t.Errorf("chain/chains.txt line missing name/summary: %q", line)
		}
		steps := strings.Split(parts[1], ",")
		if len(steps) < 2 {
			t.Errorf("chain/chains.txt %q must have at least 2 steps", parts[0])
		}
		for _, s := range steps {
			if !known[s] {
				t.Errorf("chain/chains.txt %q references unknown class id %q", parts[0], s)
			}
		}
	}
}
