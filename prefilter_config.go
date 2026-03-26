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

type prefilterConfigEnvelope struct {
	Rules     json.RawMessage `json:"rules"`
	Version   string          `json:"version"`
	UpdatedAt string          `json:"updatedAt"`
}

type PrefilterConfigStore struct {
	mu           sync.RWMutex
	rules        PrefilterRules
	lastVersion  string
	collectorURL string
	apiKey       string
}

var (
	prefilterConfigRegistryMu sync.Mutex
	prefilterConfigRegistry   = map[string]*PrefilterConfigStore{}
)

func prefilterConfigKey(collectorURL, apiKey string, refreshSec int) string {
	return collectorURL + "|" + apiKey + "|" + strconv.Itoa(refreshSec)
}

func NewPrefilterConfigStore(collectorURL string, refreshSec int, apiKey string, fallbackRules PrefilterRules) *PrefilterConfigStore {
	if refreshSec <= 0 {
		refreshSec = 30
	}

	key := prefilterConfigKey(collectorURL, apiKey, refreshSec)
	prefilterConfigRegistryMu.Lock()
	if existing, ok := prefilterConfigRegistry[key]; ok {
		prefilterConfigRegistryMu.Unlock()
		return existing
	}

	// Use operator-provided static rules as initial fallback; if zero-value, use hardcoded defaults
	initialRules := fallbackRules
	if isZeroPrefilterRules(initialRules) {
		initialRules = defaultPrefilterRules()
	}

	s := &PrefilterConfigStore{
		rules:        initialRules,
		collectorURL: collectorURL,
		apiKey:       apiKey,
	}
	prefilterConfigRegistry[key] = s
	prefilterConfigRegistryMu.Unlock()

	// Attempt initial fetch (best-effort)
	s.refresh()
	// Start background refresh loop
	go s.refreshLoop(time.Duration(refreshSec) * time.Second)

	return s
}

func (s *PrefilterConfigStore) GetRules() PrefilterRules {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rules := s.rules
	rules.DeniedPathPrefixes = append([]string(nil), s.rules.DeniedPathPrefixes...)
	rules.DeniedUserAgentSubs = append([]string(nil), s.rules.DeniedUserAgentSubs...)
	rules.DeniedCountries = append([]string(nil), s.rules.DeniedCountries...)
	return rules
}

func (s *PrefilterConfigStore) refreshLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		s.refresh()
	}
}

func (s *PrefilterConfigStore) refresh() {
	client := &http.Client{Timeout: 3 * time.Second}
	requestURL := fmt.Sprintf("%s/prefilter-config?apiKey=%s", s.collectorURL, url.QueryEscape(s.apiKey))
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		log.Printf("[prefilter-config] refresh request create failed: %v (keeping stale data)", err)
		return
	}
	req.Header.Set("X-API-Key", s.apiKey)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[prefilter-config] refresh failed: %v (keeping stale data)", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[prefilter-config] refresh got status %d (keeping stale data)", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[prefilter-config] failed to read response: %v (keeping stale data)", err)
		return
	}

	var envelope prefilterConfigEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		log.Printf("[prefilter-config] failed to parse response envelope: %v (keeping stale data)", err)
		return
	}

	s.mu.RLock()
	lastVersion := s.lastVersion
	s.mu.RUnlock()
	if envelope.Version != "" && envelope.Version == lastVersion {
		log.Printf("[prefilter-config] unchanged version=%s; skipping rules update", envelope.Version)
		return
	}

	if len(envelope.Rules) == 0 || string(envelope.Rules) == "null" {
		log.Printf("[prefilter-config] missing rules object in response (keeping stale data)")
		return
	}

	var parsedRules PrefilterRules
	if err := json.Unmarshal(envelope.Rules, &parsedRules); err != nil {
		log.Printf("[prefilter-config] failed to parse rules: %v (keeping stale data)", err)
		return
	}

	if isZeroPrefilterRules(parsedRules) {
		log.Printf("[prefilter-config] zero-value rules object rejected (keeping stale data)")
		return
	}

	s.mu.Lock()
	s.rules = parsedRules
	s.lastVersion = envelope.Version
	s.mu.Unlock()

	log.Printf("[prefilter-config] refreshed rules: version=%s updatedAt=%s", envelope.Version, envelope.UpdatedAt)
}

func isZeroPrefilterRules(r PrefilterRules) bool {
	return r.URILengthMax == 0 &&
		r.QueryLengthMax == 0 &&
		r.QueryParamCountMax == 0 &&
		r.HeaderValueLengthMax == 0 &&
		len(r.DeniedPathPrefixes) == 0 &&
		len(r.DeniedUserAgentSubs) == 0 &&
		len(r.DeniedCountries) == 0
}
