// Package tls implements TLS/SSL certificate analysis and security checks.
// It examines certificate validity, protocol versions, cipher suites, and
// extracts Subject Alternative Names (SANs) which may reveal additional
// subdomains not found through DNS enumeration.
package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/QYVORA/qyvora-anansi/internal/dnscache"
	"github.com/QYVORA/qyvora-anansi/internal/output"
)

// resolver caches SAN hostname lookups so subdomains discovered from TLS
// certificates do not trigger redundant DNS queries.
var resolver = dnscache.New(net.DefaultResolver, 60*time.Second, 20000)

// probeHost establishes a TLS connection to the given hostname and extracts
// certificate metadata.  InsecureSkipVerify is deliberately enabled so that
// hosts with invalid, self-signed, or expired certificates can still be
// analysed.
func probeHost(hostname string, timeout int) (*output.TLSResult, error) {
	dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	tlsDialer := &tls.Dialer{NetDialer: dialer, Config: &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}}
	rawConn, err := tlsDialer.DialContext(context.Background(), "tcp", hostname+":443")
	if err != nil {
		return nil, err
	}
	conn, ok := rawConn.(*tls.Conn)
	if !ok {
		_ = rawConn.Close()
		return nil, fmt.Errorf("unexpected connection type %T", rawConn)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates")
	}

	cert := state.PeerCertificates[0]
	now := time.Now()
	days := int(cert.NotAfter.Sub(now).Hours() / 24)

	sans := make([]string, 0, len(cert.DNSNames))
	for _, dns := range cert.DNSNames {
		sans = append(sans, strings.TrimPrefix(dns, "*."))
	}

	issuerOrg := ""
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = cert.Issuer.Organization[0]
	} else if cert.Issuer.CommonName != "" {
		issuerOrg = cert.Issuer.CommonName
	}

	selfSigned := cert.Issuer.CommonName == cert.Subject.CommonName && len(cert.Issuer.Organization) == 0

	result := &output.TLSResult{
		Hostname:        hostname,
		Protocol:        tlsVersionName(state.Version),
		Cipher:          tls.CipherSuiteName(state.CipherSuite),
		Issuer:          issuerOrg,
		Subject:         cert.Subject.CommonName,
		ValidFrom:       cert.NotBefore.Format("2006-01-02"),
		ValidTo:         cert.NotAfter.Format("2006-01-02"),
		DaysUntilExpiry: days,
		Expired:         days < 0,
		ExpiringSoon:    days >= 0 && days <= 30,
		SelfSigned:      selfSigned,
		SANs:            sans,
	}

	result.Findings = generateFindings(result)
	return result, nil
}

// generateFindings creates vulnerability findings based on TLS certificate
// analysis: expired/expiring certs, self-signed issuers, weak protocols.
func generateFindings(r *output.TLSResult) []output.Finding {
	var findings []output.Finding

	if r.Expired {
		findings = append(findings, output.Finding{
			Severity:      output.Critical,
			Confidence:    output.Confirmed,
			Title:         "TLS Certificate Expired",
			AffectedAsset: r.Hostname,
			Description:   fmt.Sprintf("Certificate expired on %s.", r.ValidTo),
			Evidence:      fmt.Sprintf("NotAfter: %s (%d days ago)", r.ValidTo, -r.DaysUntilExpiry),
			Remediation:   "Renew the TLS certificate immediately.",
		})
	} else if r.ExpiringSoon {
		findings = append(findings, output.Finding{
			Severity:      output.High,
			Confidence:    output.Confirmed,
			Title:         fmt.Sprintf("TLS Certificate Expiring in %d Days", r.DaysUntilExpiry),
			AffectedAsset: r.Hostname,
			Evidence:      fmt.Sprintf("NotAfter: %s", r.ValidTo),
			Remediation:   "Renew the TLS certificate before expiry.",
		})
	}

	if r.SelfSigned {
		findings = append(findings, output.Finding{
			Severity:      output.High,
			Confidence:    output.Confirmed,
			Title:         "Self-Signed TLS Certificate",
			AffectedAsset: r.Hostname,
			Description:   "Certificate is not signed by a trusted CA.",
			Evidence:      fmt.Sprintf("Issuer CN: %s == Subject CN: %s", r.Issuer, r.Subject),
			Remediation:   "Replace with a certificate from a trusted CA (e.g. Let's Encrypt).",
		})
	}

	weakProtos := map[string]bool{"TLS 1.0": true, "TLS 1.1": true, "SSL 3.0": true, "SSL 2.0": true}
	if weakProtos[r.Protocol] {
		findings = append(findings, output.Finding{
			Severity:      output.High,
			Confidence:    output.Confirmed,
			Title:         fmt.Sprintf("Weak TLS Protocol: %s", r.Protocol),
			AffectedAsset: r.Hostname,
			Description:   fmt.Sprintf("Server negotiated deprecated protocol %s.", r.Protocol),
			Evidence:      fmt.Sprintf("Protocol: %s", r.Protocol),
			Remediation:   "Disable TLS 1.0 and 1.1. Enforce TLS 1.2+ only.",
		})
	}

	return findings
}

// tlsVersionName converts a Go TLS version constant to a human-readable
// string (e.g., tls.VersionTLS12 -> "TLS 1.2").
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// Run probes TLS on all hosts that responded to HTTPS and returns:
//  1. TLS analysis results (certificate info, expiry, protocol strength)
//  2. New subdomains discovered from certificate SANs
func Run(liveProbes []output.ProbeResult, targetDomain string, timeout int, threads int, delayMs int, stealth bool) ([]output.TLSResult, []output.SubdomainResult) {
	results := make([]output.TLSResult, 0)
	mu := sync.Mutex{}
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, p := range liveProbes {
		if !strings.HasPrefix(p.URL, "https://") {
			mu.Lock()
			results = append(results, output.TLSResult{
				Hostname:  p.FQDN,
				Supported: false,
				Error:     "No HTTPS support (HTTP only)",
			})
			mu.Unlock()
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(pr output.ProbeResult) {
			defer wg.Done()
			defer func() { <-sem }()
			delay := output.JitterDelay(delayMs, stealth)
			if delay > 0 {
				time.Sleep(delay)
			}
			r, err := probeHost(pr.FQDN, timeout)
			mu.Lock()
			if err != nil {
				results = append(results, output.TLSResult{
					Hostname:  pr.FQDN,
					Supported: false,
					Error:     err.Error(),
				})
			} else {
				r.Supported = true
				results = append(results, *r)
			}
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	var newSubdomains []output.SubdomainResult
	seen := map[string]struct{}{}
	for _, r := range results {
		for _, san := range r.SANs {
			san = strings.ToLower(san)
			if !strings.HasSuffix(san, "."+targetDomain) {
				continue
			}
			if _, exists := seen[san]; exists {
				continue
			}
			seen[san] = struct{}{}
			ips, _ := resolver.LookupHost(context.Background(), san)
			newSubdomains = append(newSubdomains, output.SubdomainResult{
				FQDN:     san,
				Source:   output.SourceSAN,
				IPs:      ips,
				Resolved: len(ips) > 0,
			})
		}
	}

	return results, newSubdomains
}
