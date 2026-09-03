package osint

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-anansi/internal/output"
)

var (
	tldWhoisServer = map[string]string{
		"com":  "whois.verisign-grs.com",
		"net":  "whois.verisign-grs.com",
		"org":  "whois.pir.org",
		"io":   "whois.nic.io",
		"co":   "whois.nic.co",
		"app":  "whois.nic.google",
		"dev":  "whois.nic.google",
		"xyz":  "whois.nic.xyz",
		"tech": "whois.nic.tech",
	}

	whoisOrg   = regexp.MustCompile(`(?mi)^(?:OrgName|org-name|org_name|Organization|organisation|Registrant Organization|owner|Sponsoring Registrar):\s*(.+)$`)
	whoisEmail = regexp.MustCompile(`(?mi)^(?:OrgEmail|org-email|org_email|Email|e-mail|Registrant Email|Admin Email|Tech Email):\s*(.+)$`)
	whoisName  = regexp.MustCompile(`(?mi)^(?:OrgName|org-name|org_name|Registrant Name|Admin Name|Tech Name):\s*(.+)$`)
	ianaWhois  = regexp.MustCompile(`(?mi)^whois:\s*(\S+)`)
	rawEmail   = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	rawPhone   = regexp.MustCompile(`\+\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{3,9}`)
)

type whoisContact struct {
	Name  string
	Email string
	Phone string
}

func whoisLookup(domain string) (whoisContact, []output.OSINTResult) {
	var contacts whoisContact

	// WHOIS queries are sent over plain TCP (port 43) without encryption.
	// Any data exchanged — including emails, phone numbers, and org names —
	// is visible to network observers. Do not run WHOIS lookups over
	// untrusted networks if the results are sensitive.
	results := make([]output.OSINTResult, 0)

	server := resolveWhoisServer(domain)
	if server == "" {
		return contacts, nil
	}

	body, err := queryWhois(server, domain)
	if err != nil || len(body) < 20 {
		return contacts, nil
	}

	// If the response contains a referral to another WHOIS server, follow it
	if refServer := extractReferral(body); refServer != "" {
		refBody, refErr := queryWhois(refServer, domain)
		if refErr == nil && len(refBody) > len(body) {
			body = refBody
			server = refServer
		}
	}

	contacts.Name = extractFirstMatch(whoisOrg, body)
	if contacts.Name == "" {
		contacts.Name = extractFirstMatch(whoisName, body)
	}

	contacts.Email = extractFirstMatch(whoisEmail, body)

	if contacts.Name != "" {
		results = append(results, output.OSINTResult{
			Category: "org",
			Value:    strings.TrimSpace(contacts.Name),
			Source:   fmt.Sprintf("WHOIS/%s", server),
			Context:  "registrant",
		})
	}

	seen := map[string]bool{}

	// Structured emails from WHOIS-specific fields
	if contacts.Email != "" {
		results = append(results, output.OSINTResult{
			Category: "email",
			Value:    strings.ToLower(strings.TrimSpace(contacts.Email)),
			Source:   fmt.Sprintf("WHOIS/%s", server),
			Context:  "registrant",
		})
		seen[strings.ToLower(contacts.Email)] = true
	}

	// Raw email scan for emails not caught by field-specific regex
	for _, m := range rawEmail.FindAllString(body, -1) {
		e := strings.ToLower(strings.TrimSpace(m))
		if seen[e] || strings.HasSuffix(e, ".png") || strings.HasSuffix(e, ".jpg") || strings.HasSuffix(e, ".css") || strings.HasSuffix(e, ".js") {
			continue
		}
		seen[e] = true
		results = append(results, output.OSINTResult{
			Category: "email",
			Value:    e,
			Source:   fmt.Sprintf("WHOIS/%s", server),
			Context:  "registrant",
		})
	}

	// Phone numbers — only match international format with + prefix
	for _, m := range rawPhone.FindAllString(body, -1) {
		p := strings.TrimSpace(m)
		if len(p) < 8 || len(p) > 20 {
			continue
		}
		if yearRange.MatchString(p) {
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		results = append(results, output.OSINTResult{
			Category: "phone",
			Value:    p,
			Source:   fmt.Sprintf("WHOIS/%s", server),
			Context:  "registrant",
		})
		contacts.Phone = p
	}

	return contacts, results
}

func resolveWhoisServer(domain string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(domain)), ".")
	if len(parts) < 2 {
		return ""
	}
	tld := parts[len(parts)-1]

	if srv, ok := tldWhoisServer[tld]; ok {
		return srv
	}

	// For unknown TLDs, query IANA to find the authoritative WHOIS server
	if srv := lookupIanaWhois(tld); srv != "" {
		return srv
	}

	return fmt.Sprintf("whois.nic.%s", tld)
}

func lookupIanaWhois(tld string) string {
	body, err := queryWhois("whois.iana.org", tld)
	if err != nil {
		return ""
	}
	return extractFirstMatch(ianaWhois, body)
}

func extractReferral(body string) string {
	ref := regexp.MustCompile(`(?mi)^(?:Registrar WHOIS Server|Whois Server|refer|whois server):\s*(\S+)`)
	return extractFirstMatch(ref, body)
}

func extractFirstMatch(re *regexp.Regexp, text string) string {
	matches := re.FindStringSubmatch(text)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func queryWhois(server, query string) (string, error) {
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(context.Background(), "tcp", server+":43")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	_, _ = fmt.Fprintf(conn, "%s\r\n", query)

	var lines []string
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "%") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.TrimSpace(strings.Join(lines, "\n")), scanner.Err()
}
