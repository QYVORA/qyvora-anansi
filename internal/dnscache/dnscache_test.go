package dnscache

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestNewDefaults verifies sensible defaults when zero values are passed.
func TestNewDefaults(t *testing.T) {
	c := New(nil, 0, 0)
	if c.ttl != 60*time.Second {
		t.Errorf("default ttl = %v, want 60s", c.ttl)
	}
	if c.maxEntries != 10000 {
		t.Errorf("default maxEntries = %d, want 10000", c.maxEntries)
	}
	if c.resolver == nil {
		t.Error("resolver should fall back to net.DefaultResolver")
	}
}

// TestCacheHitAndMiss exercises the internal cache directly.
func TestCacheHitAndMiss(t *testing.T) {
	c := New(nil, time.Hour, 10)
	if _, ok := c.get("a.example"); ok {
		t.Fatal("unexpected cache hit before put")
	}
	c.put("a.example", []string{"1.2.3.4", "1.2.3.5"})
	v, ok := c.get("a.example")
	if !ok || len(v) != 2 || v[0] != "1.2.3.4" {
		t.Fatalf("cache hit = %v, %v", v, ok)
	}
}

// TestCacheExpiry verifies expired entries are dropped on read.
func TestCacheExpiry(t *testing.T) {
	c := New(nil, -1*time.Millisecond, 10) // ttl <= 0 becomes 60s, so set directly
	c.ttl = time.Millisecond
	c.put("a.example", []string{"1.2.3.4"})
	time.Sleep(5 * time.Millisecond)
	if _, ok := c.get("a.example"); ok {
		t.Error("expired entry should be evicted")
	}
}

// TestCacheMaxEntriesClear verifies the store resets when it overflows.
func TestCacheMaxEntriesClear(t *testing.T) {
	c := New(nil, time.Hour, 3)
	c.put("k1", []string{"1"})
	c.put("k2", []string{"1"})
	c.put("k3", []string{"1"})
	// Fourth put exceeds capacity and wipes the map.
	c.put("k4", []string{"1"})
	if _, ok := c.get("k1"); ok {
		t.Error("overflow should clear prior entries")
	}
	if _, ok := c.get("k4"); !ok {
		t.Error("newest entry must survive the clear")
	}
}

// TestLookupHostUsesCache proves cached results are returned without touching
// the underlying resolver: the resolver's Dial hangs/errors, yet a primed
// cache entry still resolves instantly.
func TestLookupHostUsesCache(t *testing.T) {
	broken := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, &net.DNSError{Err: "blackhole", IsTimeout: true}
		},
	}
	c := New(broken, time.Hour, 10)
	c.mu.Lock()
	c.put("a.example", []string{"10.0.0.7"})
	c.mu.Unlock()

	ips, err := c.LookupHost(context.Background(), "a.example")
	if err != nil {
		t.Fatalf("LookupHost should hit the cache, got error: %v", err)
	}
	if len(ips) != 1 || ips[0] != "10.0.0.7" {
		t.Errorf("LookupHost = %v", ips)
	}
}

// TestLookupHostPropagatesResolverError ensures misses forward real resolver
// failures rather than swallowing them.
func TestLookupHostPropagatesResolverError(t *testing.T) {
	broken := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, &net.DNSError{Err: "blackhole", IsTimeout: true}
		},
	}
	c := New(broken, time.Hour, 10)
	if _, err := c.LookupHost(context.Background(), "missing.example"); err == nil {
		t.Error("expected a resolver error for a cache miss")
	}
}

// TestLookupCNAMEEmptyResultPreserved verifies an empty cached CNAME round
// trips through the cache path without panicking.
func TestLookupCNAMEEmptyResultPreserved(t *testing.T) {
	c := New(nil, time.Hour, 10)
	c.mu.Lock()
	c.put("cname:x.example", []string{})
	c.mu.Unlock()
	cname, err := c.LookupCNAME(context.Background(), "x.example")
	if err == nil {
		t.Errorf("expected error for cached empty CNAME, got %q", cname)
	}
}
