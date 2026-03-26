package traefik_protector_mirror

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// blocklistResponse is the JSON format returned by GET /blocklist.
type blocklistResponse struct {
	Blocked []string `json:"blocked"`
}

// Blocklist maintains an in-memory set of blocked fingerprint IDs,
// periodically refreshed from the Collector service.
type Blocklist struct {
	mu           sync.RWMutex
	blocked      map[string]bool
	collectorURL string
	apiKey       string
}

var (
	blocklistRegistryMu sync.Mutex
	blocklistRegistry   = map[string]*Blocklist{}
)

func blocklistKey(collectorURL, apiKey string, refreshSec int) string {
	return collectorURL + "|" + apiKey + "|" + strconv.Itoa(refreshSec)
}

// NewBlocklist creates a new Blocklist and starts a background refresh loop.
func NewBlocklist(collectorURL string, refreshSec int, apiKey string) *Blocklist {
	if refreshSec <= 0 {
		refreshSec = 5
	}

	key := blocklistKey(collectorURL, apiKey, refreshSec)
	blocklistRegistryMu.Lock()
	if existing, ok := blocklistRegistry[key]; ok {
		blocklistRegistryMu.Unlock()
		return existing
	}

	b := &Blocklist{
		blocked:      make(map[string]bool),
		collectorURL: collectorURL,
		apiKey:       apiKey,
	}
	blocklistRegistry[key] = b
	blocklistRegistryMu.Unlock()

	// Attempt initial fetch (best-effort)
	b.refresh()
	// Start background refresh loop
	go b.refreshLoop(time.Duration(refreshSec) * time.Second)
	return b
}

// IsBlocked returns true if the given fingerprint ID is in the blocklist.
// The blocklist only contains fingerprints with status "blocked" (as returned
// by the Collector's /blocklist endpoint). Fingerprints with status "sandboxed"
// or "throttled" are NOT included — those statuses are not yet enforced.
func (b *Blocklist) IsBlocked(fingerprintID string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.blocked[fingerprintID]
}

// refreshLoop periodically refreshes the blocklist from the Collector.
func (b *Blocklist) refreshLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		b.refresh()
	}
}

// refresh fetches the current blocklist from the Collector.
// On failure, the existing blocklist is kept (stale data is acceptable).
func (b *Blocklist) refresh() {
	client := &http.Client{Timeout: 3 * time.Second}
	requestURL := fmt.Sprintf("%s/blocklist?apiKey=%s", b.collectorURL, url.QueryEscape(b.apiKey))
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		log.Printf("[blocklist] refresh request create failed: %v (keeping stale data)", err)
		return
	}
	req.Header.Set("X-API-Key", b.apiKey)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[blocklist] refresh failed: %v (keeping stale data)", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[blocklist] refresh got status %d (keeping stale data)", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[blocklist] failed to read response: %v", err)
		return
	}

	var result blocklistResponse
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("[blocklist] failed to parse response: %v", err)
		return
	}

	newBlocked := make(map[string]bool, len(result.Blocked))
	for _, fid := range result.Blocked {
		newBlocked[fid] = true
	}

	b.mu.Lock()
	b.blocked = newBlocked
	b.mu.Unlock()

	log.Printf("[blocklist] refreshed: %d blocked users", len(newBlocked))
}
