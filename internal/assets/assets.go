// Package assets provides access to embedded wordlists and configuration files.
// Go's //go:embed directive compiles these files directly into the binary so
// no external file dependencies exist at runtime.  When a matching file also
// exists on the local filesystem, the local copy is preferred (useful for
// custom wordlist development).
package assets

import (
	"embed"
	"os"
	"path/filepath"
	"strings"
)

// EmbeddedAssets holds all wordlists compiled into the binary via //go:embed.
//
//go:embed wordlists/**/*.txt
var EmbeddedAssets embed.FS

// LoadData reads a file from the given path.  It first tries the local
// filesystem; if that fails it falls back to the embedded copy.  Blank
// lines and comment lines (starting with #) are stripped from the result.
func LoadData(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		embedPath := filepath.ToSlash(path)
		data, err = EmbeddedAssets.ReadFile(embedPath)
	}

	if err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			result = append(result, trimmed)
		}
	}
	return result
}

// LoadWordlist loads a subdomain wordlist.  If customPath is non-empty it
// is used directly; otherwise the built-in "default.txt" or "deep.txt"
// (controlled by the deep parameter) is returned from the embedded assets.
func LoadWordlist(customPath string, deep bool) []string {
	if customPath != "" {
		return LoadData(customPath)
	}

	filename := "default.txt"
	if deep {
		filename = "deep.txt"
	}

	return LoadData(filepath.Join("wordlists", "subdomains", filename))
}
