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
