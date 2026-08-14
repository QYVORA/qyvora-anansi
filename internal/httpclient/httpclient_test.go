package httpclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFollowRedirects caps redirects at the configured maximum (3) and
// stops short of following forever.
func TestFollowRedirects(t *testing.T) {
	hops := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, "/hop", http.StatusFound)
	}))
	defer srv.Close()

	client := NewFollowRedirects(5)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	// Redirect loop must be cut at the redirect cap, not run forever.
	if hops != 4 {
		t.Errorf("server received %d requests, want 4 (original + 3 redirects)", hops)
	}
	if resp.StatusCode != http.StatusFound {
		t.Errorf("final status = %d, want 302 (redirect chain stopped)", resp.StatusCode)
	}
}

// TestNoRedirect never follows a redirect.
func TestNoRedirect(t *testing.T) {
	hops := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, "/hop", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	client := NewNoRedirect(5)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if hops != 1 {
		t.Errorf("server received %d requests, want 1", hops)
	}
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("final status = %d, want 301", resp.StatusCode)
	}
}

// TestNegativeRedirectsDisablesFollowing treats a negative maxRedirects as
// "never follow", like NewNoRedirect.
func TestNegativeRedirectsDisablesFollowing(t *testing.T) {
	hops := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, "/hop", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	client := New(5, -1)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if hops != 1 {
		t.Errorf("server received %d requests, want 1", hops)
	}
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("final status = %d, want 307", resp.StatusCode)
	}
}

// TestNonPositiveTimeoutMeansNoTimeout ensures a timeoutSec <= 0 yields an
// unlimited client rather than a degenerate deadline.
func TestNonPositiveTimeoutMeansNoTimeout(t *testing.T) {
	c := New(0, 3)
	if c.Timeout != 0 {
		t.Errorf("Timeout = %v, want zero for timeoutSec<=0", c.Timeout)
	}
}

// TestSharedTransportReuse verifies all clients share one connection pool.
func TestSharedTransportReuse(t *testing.T) {
	if New(5, 0).Transport != sharedTransport {
		t.Error("New should reuse the shared transport")
	}
	if NewFollowRedirects(5).Transport != sharedTransport {
		t.Error("NewFollowRedirects should reuse the shared transport")
	}
}
