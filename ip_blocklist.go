package traefik_protector_mirror

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// IPBlocklist maintains an in-memory set of blocked IP addresses,
// periodically refreshed from the Collector's /ip-blocklist endpoint.
type IPBlocklist struct {
	mu           sync.RWMutex
	blocked      map[string]bool
	collectorURL string
	apiKey       string
}

// NewIPBlocklist creates a new IPBlocklist and starts a background refresh loop.
func NewIPBlocklist(collectorURL string, refreshSec int, apiKey string) *IPBlocklist {
	b := &IPBlocklist{
		blocked:      make(map[string]bool),
		collectorURL: collectorURL,
		apiKey:       apiKey,
	}
	// Attempt initial fetch (best-effort)
	b.refresh()
	// Start background refresh loop
	go b.refreshLoop(time.Duration(refreshSec) * time.Second)
	return b
}

// IsBlocked returns true if the given IP address is in the IP blocklist.
func (b *IPBlocklist) IsBlocked(ip string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.blocked[ip]
}

// refreshLoop periodically refreshes the IP blocklist from the Collector.
func (b *IPBlocklist) refreshLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		b.refresh()
	}
}

// refresh fetches the current IP blocklist from the Collector.
// On failure, the existing blocklist is kept (stale data is acceptable).
func (b *IPBlocklist) refresh() {
	client := &http.Client{Timeout: 3 * time.Second}
	requestURL := fmt.Sprintf("%s/ip-blocklist?apiKey=%s", b.collectorURL, url.QueryEscape(b.apiKey))
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		log.Printf("[ip-blocklist] refresh request create failed: %v (keeping stale data)", err)
		return
	}
	req.Header.Set("X-API-Key", b.apiKey)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ip-blocklist] refresh failed: %v (keeping stale data)", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[ip-blocklist] refresh got status %d (keeping stale data)", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ip-blocklist] failed to read response: %v", err)
		return
	}

	var result blocklistResponse
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("[ip-blocklist] failed to parse response: %v", err)
		return
	}

	newBlocked := make(map[string]bool, len(result.Blocked))
	for _, ip := range result.Blocked {
		newBlocked[ip] = true
	}

	b.mu.Lock()
	b.blocked = newBlocked
	b.mu.Unlock()

	log.Printf("[ip-blocklist] refreshed: %d blocked IPs", len(newBlocked))
}
