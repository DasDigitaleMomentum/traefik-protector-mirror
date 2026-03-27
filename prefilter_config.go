package traefik_protector_mirror

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type prefilterConfigEnvelope struct {
	Rules     json.RawMessage `json:"rules"`
	Version   string          `json:"version"`
	UpdatedAt string          `json:"updatedAt"`
}

type PrefilterConfigStore struct {
	mu            sync.RWMutex
	rules         PrefilterRules
	fallbackRules PrefilterRules
	lastVersion   string
	collectorURL  string
	apiKey        string
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
	preparedInitialRules, err := prepareRulesForStorage(initialRules)
	if err != nil {
		log.Printf("[prefilter-config] invalid initial fallback rules: %v; using defaults", err)
		preparedInitialRules, _ = prepareRulesForStorage(defaultPrefilterRules())
	}

	s := &PrefilterConfigStore{
		rules:         preparedInitialRules,
		fallbackRules: preparedInitialRules,
		collectorURL:  collectorURL,
		apiKey:        apiKey,
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
	rules.DeniedPathRegexes = append([]string(nil), s.rules.DeniedPathRegexes...)
	rules.DeniedUserAgentSubs = append([]string(nil), s.rules.DeniedUserAgentSubs...)
	rules.DeniedCountries = append([]string(nil), s.rules.DeniedCountries...)
	rules.compiledDeniedPathRegexes = append([]*regexp.Regexp(nil), s.rules.compiledDeniedPathRegexes...)
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
		// Collector returned empty rules — reset to operator-provided fallback
		s.mu.Lock()
		s.rules = s.fallbackRules
		s.lastVersion = envelope.Version
		s.mu.Unlock()
		log.Printf("[prefilter-config] collector returned zero-value rules; reset to fallback (version=%s)", envelope.Version)
		return
	}

	s.mu.RLock()
	baseline := s.rules
	s.mu.RUnlock()

	merged := mergePrefilterRules(baseline, parsedRules)
	preparedRules, err := prepareRulesForStorage(merged)
	if err != nil {
		log.Printf("[prefilter-config] invalid merged rules: %v (keeping stale data)", err)
		return
	}

	s.mu.Lock()
	s.rules = preparedRules
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
		len(r.DeniedPathRegexes) == 0 &&
		len(r.DeniedUserAgentSubs) == 0 &&
		len(r.DeniedCountries) == 0
}

func mergePrefilterRules(base PrefilterRules, incoming PrefilterRules) PrefilterRules {
	merged := base

	if incoming.URILengthMax > 0 {
		merged.URILengthMax = incoming.URILengthMax
	}
	if incoming.QueryLengthMax > 0 {
		merged.QueryLengthMax = incoming.QueryLengthMax
	}
	if incoming.QueryParamCountMax > 0 {
		merged.QueryParamCountMax = incoming.QueryParamCountMax
	}
	if incoming.HeaderValueLengthMax > 0 {
		merged.HeaderValueLengthMax = incoming.HeaderValueLengthMax
	}
	if len(incoming.DeniedPathPrefixes) > 0 {
		merged.DeniedPathPrefixes = append([]string(nil), incoming.DeniedPathPrefixes...)
	}
	if len(incoming.DeniedPathRegexes) > 0 {
		merged.DeniedPathRegexes = append([]string(nil), incoming.DeniedPathRegexes...)
	}
	if len(incoming.DeniedUserAgentSubs) > 0 {
		merged.DeniedUserAgentSubs = append([]string(nil), incoming.DeniedUserAgentSubs...)
	}
	if len(incoming.DeniedCountries) > 0 {
		merged.DeniedCountries = append([]string(nil), incoming.DeniedCountries...)
	}

	return merged
}

func prepareRulesForStorage(rules PrefilterRules) (PrefilterRules, error) {
	rules.DeniedPathPrefixes = normalizeStringList(rules.DeniedPathPrefixes)
	rules.DeniedPathRegexes = normalizeStringList(rules.DeniedPathRegexes)
	rules.DeniedUserAgentSubs = normalizeStringList(rules.DeniedUserAgentSubs)
	rules.DeniedCountries = normalizeStringList(rules.DeniedCountries)

	compiled := make([]*regexp.Regexp, 0, len(rules.DeniedPathRegexes))
	for _, expr := range rules.DeniedPathRegexes {
		re, err := regexp.Compile(expr)
		if err != nil {
			return PrefilterRules{}, fmt.Errorf("invalid deniedPathRegex %q: %w", expr, err)
		}
		compiled = append(compiled, re)
	}
	rules.compiledDeniedPathRegexes = compiled

	return rules, nil
}

func normalizeStringList(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	return normalized
}
