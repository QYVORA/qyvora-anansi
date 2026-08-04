package osint

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/QYVORA/qyvora-anansi-cli/internal/output"
)

var (
	emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	phonePattern = regexp.MustCompile(`(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{3,9}`)
	yearRange    = regexp.MustCompile(`^\d{4}\s*[-–]\s*\d{4}$`)
	namePattern  = regexp.MustCompile(`(?i)(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)`)
	skipPrefix   = []string{"http", "www", "the ", "this ", "our ", "all ", "get", "contact", "about", "team", "javascript", "function", "var ", "const", "let ", "return", "footer", "header", "copyright", "all rights"}
)

func fetchPage(client *http.Client, url string, stealth bool) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return "", err
	}

	if stealth {
		req.Header.Set("User-Agent", output.RandomUA())
	} else {
		req.Header.Set("User-Agent", output.DefaultUA)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func extractEmails(body string) []string {
	seen := map[string]bool{}
	matches := emailPattern.FindAllString(body, -1)
	results := make([]string, 0, len(matches))
	for _, match := range matches {
		email := strings.ToLower(strings.TrimSpace(match))
		if seen[email] {
			continue
		}
		seen[email] = true
		// Skip common false positives
		if strings.Contains(email, "example.com") || strings.Contains(email, ".png") || strings.Contains(email, ".jpg") || strings.Contains(email, ".css") || strings.Contains(email, ".js") {
			continue
		}
		results = append(results, email)
	}
	return results
}

func extractPhones(body string) []string {
	seen := map[string]bool{}
	matches := phonePattern.FindAllString(body, -1)
	results := make([]string, 0, len(matches))
	for _, match := range matches {
		phone := strings.TrimSpace(match)
		if len(phone) < 7 || isNumericOnly(phone) || len(phone) > 20 {
			continue
		}
		if yearRange.MatchString(phone) {
			continue
		}
		if seen[phone] {
			continue
		}
		seen[phone] = true
		results = append(results, phone)
	}
	return results
}

func extractEmployeeNames(body string) []string {
	seen := map[string]bool{}
	results := make([]string, 0)
	// Remove HTML tags to get clean text
	text := stripHTML(body)

	// Remove script and style content
	text = removeScriptStyle(text)

	for _, match := range namePattern.FindAllString(text, -1) {
		name := strings.TrimSpace(match)
		if seen[name] {
			continue
		}

		// Filter out non-name matches
		if !isLikelyName(name) {
			continue
		}

		seen[name] = true
		results = append(results, name)
	}
	return results
}

func isNumericOnly(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func stripHTML(html string) string {
	var result strings.Builder
	inTag := false
	for _, r := range html {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			result.WriteRune(' ')
			continue
		}
		if !inTag {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func removeScriptStyle(text string) string {
	lower := strings.ToLower(text)
	var result strings.Builder
	i := 0
	for i < len(text) {
		scriptIdx := strings.Index(lower[i:], "<script")
		styleIdx := strings.Index(lower[i:], "<style")
		closest := -1
		endTag := ""
		if scriptIdx != -1 && (closest == -1 || scriptIdx < closest) {
			closest = scriptIdx
			endTag = "</script>"
		}
		if styleIdx != -1 && (closest == -1 || styleIdx < closest) {
			closest = styleIdx
			endTag = "</style>"
		}
		if closest == -1 {
			result.WriteString(text[i:])
			break
		}
		result.WriteString(text[i : i+closest])
		endIdx := strings.Index(strings.ToLower(text[i+closest:]), endTag)
		if endIdx == -1 {
			break
		}
		i += closest + endIdx + len(endTag)
	}
	return result.String()
}

func isLikelyName(name string) bool {
	words := strings.Fields(name)
	if len(words) < 2 || len(words) > 5 {
		return false
	}
	// Each word should start with uppercase
	for _, w := range words {
		if len(w) < 2 {
			return false
		}
		if w[0] < 'A' || w[0] > 'Z' {
			return false
		}
	}
	// Exclude common non-name phrases
	lower := strings.ToLower(name)
	for _, prefix := range skipPrefix {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return true
}
