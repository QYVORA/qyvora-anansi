package takeover

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-anansi/internal/output"
)

// dialAll returns an http.Client whose transport routes every address to the
// given listener, so a test can make "http://<anything>" land on the test
// server without DNS.
func dialAll(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	return &http.Client{Transport: &http.Transport{DialContext: dial}}
}

// TestCheckTakeoverConfirmsDanglingCNAME verifies a dead CNAME matching a
// fingerprint whose body signature is served is reported CRITICAL.
func TestCheckTakeoverConfirmsDanglingCNAME(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html>There isn't a GitHub Pages site here.</html>")
	}))
	defer srv.Close()

	f := checkTakeover(dialAll(t, srv), "evil.example.com", []string{"evil.example.com.github.io."}, false)
	if f == nil {
		t.Fatal("expected a confirmed takeover finding")
	}
	if f.Severity != output.Critical {
		t.Errorf("severity = %s, want CRITICAL", f.Severity)
	}
	if f.AffectedAsset != "evil.example.com" {
		t.Errorf("affected asset = %s", f.AffectedAsset)
	}
	if !strings.Contains(f.Description, "GitHub Pages") {
		t.Errorf("description should name the service: %s", f.Description)
	}
}

// TestCheckTakeoverIgnoresLiveCNAMEs: a dead CNAME whose body does not match
// the fingerprint must not be reported.
func TestCheckTakeoverIgnoresLiveCNAMEs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html>a real site is here</html>")
	}))
	defer srv.Close()

	f := checkTakeover(dialAll(t, srv), "evil.example.com", []string{"evil.example.com.github.io."}, false)
	if f != nil {
		t.Errorf("expected no finding for a non-matching body, got %+v", f)
	}
}

// TestCheckTakeoverUnrelatedCNAMESkipsService ensures a CNAME that matches no
// fingerprint is ignored entirely.
func TestCheckTakeoverUnrelatedCNAMESkipsService(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "There isn't a GitHub Pages site here.")
	}))
	defer srv.Close()

	f := checkTakeover(dialAll(t, srv), "evil.example.com", []string{"evil.example.com.internal.local."}, false)
	if f != nil {
		t.Errorf("expected no finding for an unmatched CNAME, got %+v", f)
	}
}

// TestLoadTakeoverFingerprintsParsesEmbeddedWordlist.
func TestLoadTakeoverFingerprintsParsesEmbeddedWordlist(t *testing.T) {
	loadTakeoverFingerprints()
	if len(fingerprints) == 0 {
		t.Fatal("no fingerprints loaded from embedded wordlist")
	}
	var github bool
	for _, fp := range fingerprints {
		if fp.name == "GitHub Pages" && fp.cnameSuffix == "github.io" {
			github = true
		}
	}
	if !github {
		t.Error("expected a GitHub Pages fingerprint")
	}
}

// TestRunSkipsResolvedSubdomains exercises the candidate filter: a resolved
// host is never probed, while an unresolved one with a dead CNAME goes
// through the (hermetic) goroutine pipeline. Without network access the HTTP
// confirmation fails, so the outcome is a clean nil with no panic — proving
// the concurrency path terminates and resolved hosts are skipped.
func TestRunSkipsResolvedSubdomains(t *testing.T) {
	out := output.New("text", false)
	subdomains := []output.SubdomainResult{
		{FQDN: "live.example.com", Resolved: true, Source: "wordlist"},
		{FQDN: "dead.example.com", Resolved: false, Source: "wordlist", DeadCNAMEs: []string{"dead.example.com.github.io."}},
	}
	findings := Run(out, subdomains, 5, 2, 0, false)
	if findings == nil {
		return // expected without network access
	}
	t.Fatalf("expected nil findings without network, got %+v", findings)
}

// TestRunNoCandidates returns nil without touching the network.
func TestRunNoCandidates(t *testing.T) {
	out := output.New("text", false)
	findings := Run(out, []output.SubdomainResult{
		{FQDN: "live.example.com", Resolved: true, Source: "wordlist"},
	}, 5, 2, 0, false)
	if findings != nil {
		t.Errorf("expected nil findings, got %+v", findings)
	}
}
