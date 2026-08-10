package paths

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/QYVORA/qyvora-anansi-cli/internal/httpclient"
)

func TestLoadRules(t *testing.T) {
	rules := loadRules("wordlists/paths/default.txt")
	if len(rules) == 0 {
		t.Fatal("loadRules returned empty rules from default.txt")
	}
	var emptyPath, emptySeverity int
	for i, r := range rules {
		if r.path == "" {
			emptyPath++
		}
		if r.severity == "" {
			t.Errorf("rules[%d] has empty severity", i)
			emptySeverity++
		}
	}
	if emptyPath == len(rules) {
		t.Fatal("all rules have empty paths")
	}
	if emptySeverity > 0 {
		t.Fatalf("%d rules have empty severity", emptySeverity)
	}
}

func TestLoadRulesDeep(t *testing.T) {
	rules := loadRules("wordlists/paths/deep.txt")
	if len(rules) == 0 {
		t.Fatal("loadRules returned empty rules from deep.txt")
	}
}

func TestLoadFocusedWordlists(t *testing.T) {
	for _, name := range []string{"wordlists/paths/js.txt", "wordlists/paths/sensitive.txt"} {
		rules := loadRules(name)
		if len(rules) == 0 {
			t.Errorf("loadRules(%q) returned empty rules", name)
			continue
		}
		for i, r := range rules {
			if r.path == "" || r.title == "" || r.severity == "" {
				t.Errorf("%s: rules[%d] has empty path/title/severity", name, i)
			}
		}
	}
}

func TestLoadExtensions(t *testing.T) {
	exts := LoadExtensions()
	if len(exts) == 0 {
		t.Fatal("LoadExtensions returned no extensions")
	}
	seen := map[string]bool{}
	for _, e := range exts {
		if e[0] != '.' {
			t.Errorf("extension %q is not dot-prefixed", e)
		}
		if seen[e] {
			t.Errorf("duplicate extension %q", e)
		}
		seen[e] = true
	}
}

func TestLoadRulesNonexistent(t *testing.T) {
	rules := loadRules("/nonexistent/rules.txt")
	if rules != nil {
		t.Fatal("loadRules for nonexistent file should return nil")
	}
}

func TestExtraPathsFromRobots(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\nDisallow: /backup/*\nAllow: /public\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	client := httpclient.NewNoRedirect(5)
	rules := extraPathsFromRobots(client, srv.URL)
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (wildcard skipped), got %d: %+v", len(rules), rules)
	}
	paths := map[string]bool{}
	for _, r := range rules {
		paths[r.path] = true
	}
	if !paths["/admin"] || !paths["/public"] {
		t.Errorf("unexpected parsed paths: %v", paths)
	}
}
