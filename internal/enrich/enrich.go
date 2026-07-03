package enrich

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"example.com/packet-analyser/internal/geo"
	"example.com/packet-analyser/internal/stats"
)

type Service struct {
	geo   *geo.Lookup
	cache *simpleCache
}

func New(g *geo.Lookup) *Service {
	return &Service{
		geo:   g,
		cache: newSimpleCache(30 * time.Minute),
	}
}

// Enrich populates location, vendor, OS guess and hostname fields.
// It is safe to call from the hot packet path: DNS uses a cache + 50 ms timeout.
func (s *Service) Enrich(pkt *stats.Packet) {
	// MAC → Vendor (fast table lookup)
	if pkt.SrcMAC != "" {
		pkt.SrcVendor = LookupOUI(pkt.SrcMAC)
	}
	if pkt.DstMAC != "" {
		pkt.DstVendor = LookupOUI(pkt.DstMAC)
	}

	// TTL → OS fingerprint
	pkt.OSGuess = GuessOSFromTTL(pkt.TTL)

	// GeoIP (local MMDB — fast)
	if s.geo != nil {
		if loc, err := s.geo.Locate(pkt.SrcIP, 1); err == nil {
			pkt.SrcLocation = &stats.Location{
				IP: loc.IP, City: loc.City, Country: loc.Country,
				Lat: loc.Lat, Lng: loc.Lng, Count: loc.Count,
			}
		}
		if loc, err := s.geo.Locate(pkt.DstIP, 1); err == nil {
			pkt.DstLocation = &stats.Location{
				IP: loc.IP, City: loc.City, Country: loc.Country,
				Lat: loc.Lat, Lng: loc.Lng, Count: loc.Count,
			}
		}
	}

	// Reverse DNS (cached, 50 ms timeout per unique IP)
	pkt.SrcHost = s.cachedHostLookup(pkt.SrcIP)
	pkt.DstHost = s.cachedHostLookup(pkt.DstIP)
}

func (s *Service) cachedHostLookup(ip string) string {
	if host, ok := s.cache.Get(ip); ok {
		return host
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	type result struct{ host string }
	done := make(chan result, 1)

	go func() {
		names, err := net.LookupAddr(ip)
		if err != nil || len(names) == 0 {
			done <- result{host: ""}
			return
		}
		done <- result{host: strings.TrimSuffix(names[0], ".")}
	}()

	select {
	case <-ctx.Done():
		return ""
	case r := <-done:
		if r.host != "" {
			s.cache.Set(ip, r.host)
		}
		return r.host
	}
}

// ── simple in-memory TTL cache ───────────────────────────────────────────────

type simpleCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	value  string
	expiry time.Time
}

func newSimpleCache(ttl time.Duration) *simpleCache {
	c := &simpleCache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
	}
	go c.cleanup()
	return c
}

func (c *simpleCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.expiry) {
		return "", false
	}
	return e.value, true
}

func (c *simpleCache) Set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{value: value, expiry: time.Now().Add(c.ttl)}
}

func (c *simpleCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.expiry) {
				delete(c.entries, k)
			}
		}
		c.mu.Unlock()
	}
}