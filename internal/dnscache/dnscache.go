// Package dnscache provides a thread-safe, TTL-expiring DNS resolver cache.
// The same candidate subdomains are frequently resolved multiple times across
// discovery, recursive, mutation, TLS SAN, and takeover phases; caching avoids
// repeated UDP/TCP round-trips to the resolver and cuts scan wall time.
package dnscache

import (
	"context"
	"net"
	"sync"
	"time"
)

type entry struct {
	values   []string
	expireAt time.Time
}

// Cache wraps a net.Resolver with a small map-based cache.  Entries expire
// after a fixed TTL.  When the map grows beyond maxEntries it is cleared to
// bound memory usage (a full clear is cheaper than per-entry LRU eviction and
// is correct because stale DNS data expires quickly anyway).
type Cache struct {
	mu         sync.Mutex
	resolver   *net.Resolver
	ttl        time.Duration
	maxEntries int
	store      map[string]entry
}

// New returns a Cache wrapping r with the given TTL and capacity.
func New(r *net.Resolver, ttl time.Duration, maxEntries int) *Cache {
	if r == nil {
		r = net.DefaultResolver
	}
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	return &Cache{
		resolver:   r,
		ttl:        ttl,
		maxEntries: maxEntries,
		store:      make(map[string]entry),
	}
}

func (c *Cache) get(key string) ([]string, bool) {
	e, ok := c.store[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expireAt) {
		delete(c.store, key)
		return nil, false
	}
	return e.values, true
}

func (c *Cache) put(key string, values []string) {
	if len(c.store) >= c.maxEntries {
		c.store = make(map[string]entry)
	}
	c.store[key] = entry{values: values, expireAt: time.Now().Add(c.ttl)}
}

// LookupHost resolves host to IP addresses, caching the result.
func (c *Cache) LookupHost(ctx context.Context, host string) ([]string, error) {
	c.mu.Lock()
	if v, ok := c.get(host); ok {
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()

	ips, err := c.resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.put(host, ips)
	c.mu.Unlock()
	return ips, nil
}

// LookupCNAME resolves the canonical name for host, caching the result.
func (c *Cache) LookupCNAME(ctx context.Context, host string) (string, error) {
	key := "cname:" + host
	c.mu.Lock()
	if v, ok := c.get(key); ok {
		c.mu.Unlock()
		if len(v) == 0 {
			return "", &net.DNSError{Name: host, Err: "cname cached empty"}
		}
		return v[0], nil
	}
	c.mu.Unlock()

	cname, err := c.resolver.LookupCNAME(ctx, host)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.put(key, []string{cname})
	c.mu.Unlock()
	return cname, nil
}
