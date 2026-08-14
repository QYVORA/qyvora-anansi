// Package httpclient provides a single, connection-pooled HTTP client shared
// by every scan module.  Connection reuse (keep-alives) across phases is the
// single largest speed win for multi-request scans: it avoids paying TCP
// handshake + TLS negotiation costs for every individual probe.
package httpclient

import (
	"crypto/tls"
	"net/http"
	"time"
)

// sharedTransport is a process-wide transport whose idle connection pool is
// reused by every module and every request.  Because all clients share this
// transport, connections established during one scan phase are reused by the
// next — a major wall-clock win on targets with many hosts.
var sharedTransport = &http.Transport{
	TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	MaxIdleConns:          1024,
	MaxIdleConnsPerHost:   64,
	MaxConnsPerHost:       0,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: time.Second,
	ForceAttemptHTTP2:     true,
}

// New builds a pooled client that follows up to maxRedirects redirects.
// A negative maxRedirects disables redirect following.  All clients returned
// by this package share one connection pool.
func New(timeoutSec int, maxRedirects int) *http.Client {
	timeout := time.Duration(timeoutSec) * time.Second
	if timeoutSec <= 0 {
		timeout = 0
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: sharedTransport,
	}
	if maxRedirects >= 0 {
		client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		}
	} else {
		// A negative maxRedirects disables redirect following entirely.
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

// NewFollowRedirects builds a pooled client following up to 3 redirects.
func NewFollowRedirects(timeoutSec int) *http.Client {
	return New(timeoutSec, 3)
}

// NewNoRedirect builds a pooled client that never follows redirects.
func NewNoRedirect(timeoutSec int) *http.Client {
	return New(timeoutSec, 0)
}
