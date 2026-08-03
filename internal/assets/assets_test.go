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
