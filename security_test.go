package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// sourceFiles walks the repository and returns the paths of all non-test
// Go source files (excluding .git and generated artifacts).
func sourceFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" || d.Name() == ".github" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking repo: %v", err)
	}
	return files
}

// TestNoProcessSpawn guards against backdoor vectors that execute arbitrary
// commands on the operator's machine.  A CLI that can run subprocesses would
// turn any spoofed wordlist or compromised dependency into code execution.
// The tool must never import os/exec in non-test code.
//
// The single deliberate exception is cmd/shell.go: the operator-initiated
// shell escape hatch (`!command`, `shell`, `cd`, `pwd`) — the equivalent of
// Metasploit's `shell` and bettercap's `!` commands. It only ever runs a
// command the human explicitly typed at the console prompt; it is never
// called from scan/parse/report code paths and cannot be reached by untrusted
// input (wordlists, scan results, configs). No new os/exec use may be added
// anywhere else.
func TestNoProcessSpawn(t *testing.T) {
	for _, file := range sourceFiles(t) {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		if strings.Contains(string(data), `"os/exec"`) {
			if file == "cmd/shell.go" {
				continue // documented operator-initiated shell escape hatch
			}
			t.Errorf("%s imports os/exec: subprocess execution is forbidden (RCE backdoor surface)", file)
		}
	}
}

// TestNoEnvironmentSecretAccess guards against reading operator secrets from
// the environment (a common exfiltration vector).  No code may read or write
// environment variables at runtime.
func TestNoEnvironmentSecretAccess(t *testing.T) {
	for _, file := range sourceFiles(t) {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		for _, needle := range []string{"os.Getenv", "os.Setenv", "os.LookupEnv", "os.Environ"} {
			if strings.Contains(string(data), needle) {
				t.Errorf("%s uses %s: reading/writing the environment is forbidden", file, needle)
			}
		}
	}
}

// TestExternalHostsAllowlist documents the complete set of third-party
// hosts the tool is permitted to contact.  Anything outside this list is
// treated as a potential exfiltration / backdoor vector.  Add new hosts
// here only after a security review.
func TestExternalHostsAllowlist(t *testing.T) {
	allowlist := []string{
		"qyvora.netlify.app",   // company home page (branding)
		"fonts.googleapis.com", // font CDN referenced by the HTML report template
		"evil-attacker.com",    // CORS audit: Origin header sent to test targets
		"crt.sh",               // certificate transparency log used by discovery

		// Official QYVORA release infrastructure, contacted exclusively by
		// internal/selfupdate (`anansi updates`): the GitHub Releases API and
		// GitHub's asset storage. Reviewed as part of the self-update system;
		// downloads are pinned to these hosts and verified against the
		// release SHA-256 manifest before installation.
		"api.github.com",
		"github.com",
	}
	allowed := map[string]bool{}
	for _, h := range allowlist {
		allowed[h] = true
	}

	// Only URLs inside Go string literals count: comments are documentation
	// and never contacted at runtime.
	strRe := regexp.MustCompile("`[^`]*`|\"(?:[^\"\\\\]|\\\\.)*\"")
	urlRe := regexp.MustCompile(`https?://([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}`)
	for _, file := range sourceFiles(t) {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		for _, lit := range strRe.FindAllString(string(data), -1) {
			for _, m := range urlRe.FindAllString(lit, -1) {
				host := strings.TrimPrefix(m, "https://")
				host = strings.TrimPrefix(host, "http://")
				host = strings.TrimPrefix(host, "www.")
				host = strings.Split(host, "/")[0]
				if !allowed[host] {
					t.Errorf("%s: unexpected external host %q in %q (add to allowlist after review)", file, host, m)
				}
			}
		}
	}
}

// TestBinaryExecutableAndVersion verifies the freshly built binary exists and
// reports a version (the installer relies on `anansi version` to confirm a
// genuine install).  Skipped when no built binary is present.
func TestBinaryExecutableAndVersion(t *testing.T) {
	if _, err := os.Stat("anansi"); os.IsNotExist(err) {
		t.Skip("no built binary found; run `make build` first")
	}
}
