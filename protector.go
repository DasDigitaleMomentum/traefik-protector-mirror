// Package traefik_protector_mirror is a Traefik middleware plugin that intercepts
// HTTP requests, computes user fingerprints, enforces a blocklist, and
// asynchronously forwards request events to the Collector service.
package traefik_protector_mirror

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var defaultTrustedProxyCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"::1/128",
	"fc00::/7",
}

// Config holds the plugin configuration from Traefik dynamic config.
type Config struct {
	CollectorURL        string         `json:"collectorURL"`
	GeoIPServiceURL     string         `json:"geoIPServiceURL"`
	BlocklistRefreshSec int            `json:"blocklistRefreshSec"`
	PrefilterRefreshSec int            `json:"prefilterRefreshSec"`
	APIKey              string         `json:"apiKey"`
	TrustedProxyCIDRs   []string       `json:"trustedProxyCIDRs"`
	PrefilterEnabled    bool           `json:"prefilterEnabled"`
	PrefilterMode       string         `json:"prefilterMode"`
	PrefilterFailMode   string         `json:"prefilterFailMode"`
	PrefilterRules      PrefilterRules `json:"prefilterRules"`

	SyncToCollectorOnPrefilterHit      bool `json:"syncToCollectorOnPrefilterHit"`
	EmitSyntheticEventOnPrefilterHit   bool `json:"emitSyntheticEventOnPrefilterHit"`
	AutoBlockFingerprintOnPrefilterHit bool `json:"autoBlockFingerprintOnPrefilterHit"`
}

// GeoIPResolver provides a seam for future GeoIP integration.
type GeoIPResolver interface {
	LookupCountry(ip string) (string, error)
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		CollectorURL:                       "http://collector:8081",
		GeoIPServiceURL:                    "",
		BlocklistRefreshSec:                5,
		PrefilterRefreshSec:                30,
		APIKey:                             "",
		TrustedProxyCIDRs:                  append([]string(nil), defaultTrustedProxyCIDRs...),
		PrefilterEnabled:                   true,
		PrefilterMode:                      "detect",
		PrefilterFailMode:                  "open",
		PrefilterRules:                     defaultPrefilterRules(),
		SyncToCollectorOnPrefilterHit:      true,
		EmitSyntheticEventOnPrefilterHit:   true,
		AutoBlockFingerprintOnPrefilterHit: true,
	}
}

// ProtectorMirror is the middleware struct.
type ProtectorMirror struct {
	next             http.Handler
	name             string
	config           *Config
	blocklist        *Blocklist
	ipBlocklist      *IPBlocklist
	prefilterConfig  *PrefilterConfigStore
	geoResolver      GeoIPResolver
	trustedProxyNets []*net.IPNet
	eventCh          chan []byte
	httpClient       *http.Client
}

type httpGeoIPResolver struct {
	baseURL    string
	httpClient *http.Client
}

type geoIPLookupResponse struct {
	CountryCode string `json:"countryCode"`
}

func (r *httpGeoIPResolver) LookupCountry(ip string) (string, error) {
	trimmedIP := strings.TrimSpace(ip)
	if trimmedIP == "" {
		return "", fmt.Errorf("missing ip for geoip lookup")
	}

	requestURL := strings.TrimRight(r.baseURL, "/") + "/lookup/" + url.PathEscape(trimmedIP)
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("geoip lookup returned status %d", resp.StatusCode)
	}

	var out geoIPLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}

	countryCode := strings.TrimSpace(out.CountryCode)
	if countryCode == "" {
		return "", fmt.Errorf("geoip response missing countryCode")
	}

	return strings.ToUpper(countryCode), nil
}

// eventPayload is the JSON sent to the Collector (matches Event Schema in plan.md).
type eventPayload struct {
	Timestamp     string            `json:"timestamp"`
	ClientIP      string            `json:"client_ip"`
	Method        string            `json:"method"`
	URL           string            `json:"url"`
	Headers       map[string]string `json:"headers"`
	StatusCode    int               `json:"status_code"`
	FingerprintID string            `json:"fingerprint_id"`
}

type blockedEventPayload struct {
	FingerprintID string `json:"fingerprint_id"`
	ClientIP      string `json:"client_ip"`
	BlockReason   string `json:"block_reason,omitempty"`
	PrecheckRule  string `json:"precheck_rule,omitempty"`
	Method        string `json:"method,omitempty"`
	URL           string `json:"url,omitempty"`
	Timestamp     string `json:"timestamp,omitempty"`
}

type statusUpdatePayload struct {
	Status   string `json:"status"`
	Actor    string `json:"actor,omitempty"`
	Reason   string `json:"reason,omitempty"`
	RuleName string `json:"rule_name,omitempty"`
}

// New creates a new ProtectorMirror middleware instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	log.Printf("[protector-mirror] initializing plugin: collector=%s refreshSec=%d prefilter=%t mode=%s",
		config.CollectorURL, config.BlocklistRefreshSec, config.PrefilterEnabled, config.effectivePrefilterMode())

	p := &ProtectorMirror{
		next:       next,
		name:       name,
		config:     config,
		eventCh:    make(chan []byte, 256),
		httpClient: &http.Client{Timeout: 2 * time.Second},
	}

	if len(config.TrustedProxyCIDRs) == 0 {
		config.TrustedProxyCIDRs = append([]string(nil), defaultTrustedProxyCIDRs...)
	}
	trustedNets, err := parseTrustedProxyCIDRs(config.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	p.trustedProxyNets = trustedNets

	preparedRules, err := prepareRulesForStorage(config.PrefilterRules)
	if err != nil {
		return nil, err
	}
	config.PrefilterRules = preparedRules

	if strings.TrimSpace(config.GeoIPServiceURL) != "" {
		p.geoResolver = &httpGeoIPResolver{
			baseURL:    config.GeoIPServiceURL,
			httpClient: p.httpClient,
		}
	}

	// Start blocklist refresh
	p.blocklist = NewBlocklist(config.CollectorURL, config.BlocklistRefreshSec, config.APIKey)

	// Start IP blocklist refresh
	p.ipBlocklist = NewIPBlocklist(config.CollectorURL, config.BlocklistRefreshSec, config.APIKey)

	if config.PrefilterEnabled && strings.TrimSpace(config.CollectorURL) != "" {
		p.prefilterConfig = NewPrefilterConfigStore(config.CollectorURL, config.PrefilterRefreshSec, config.APIKey, config.PrefilterRules)
	}

	// Start async event dispatcher
	go p.dispatchLoop()

	return p, nil
}

// ServeHTTP is the middleware handler.
func (p *ProtectorMirror) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// 1. Resolve client IP
	clientIP := resolveClientIP(req, p.trustedProxyNets)

	// 2. Run lightweight prefilter checks before backend forwarding.
	rules := p.config.PrefilterRules
	if p.prefilterConfig != nil {
		rules = p.prefilterConfig.GetRules()
	}
	decision, err := evaluatePrefilter(p.config, rules, p.geoResolver, clientIP, req)
	if err != nil {
		if p.config.prefilterFailClosed() {
			decision = prefilterDecision{Matched: true, Rule: "prefilter_error", Reason: "prefilter evaluation failed"}
		} else {
			log.Printf("[protector-mirror] prefilter evaluation error (fail-open): %v", err)
		}
	}

	fingerprintID := ""
	if decision.Matched {
		fingerprintID = computeFingerprint(clientIP, req.Header)
		if p.config.effectivePrefilterMode() == "enforce" {
			timestamp := time.Now().UTC().Format(time.RFC3339Nano)
			rw.WriteHeader(http.StatusForbidden)
			_, _ = rw.Write([]byte("403 Forbidden: blocked by protector-mirror (prefilter)"))
			go p.handlePrefilterHit(req, clientIP, fingerprintID, decision, timestamp)
			return
		}
		log.Printf("[protector-mirror] prefilter detect-only hit: rule=%s reason=%s target=%s", decision.Rule, decision.Reason, clientIP)
	}

	// 3. Compute fingerprint ID if not already available from prefilter path.
	if fingerprintID == "" {
		fingerprintID = computeFingerprint(clientIP, req.Header)
	}

	// 4. Check blocklist — enforcement boundary.
	// Only the "blocked" status triggers HTTP 403. Statuses "sandboxed" and
	// "throttled" are accepted by the Collector/API but have NO effect at the
	// plugin layer — they pass through like "active".
	// See collector/handler/status.go for the full status model.
	if p.blocklist.IsBlocked(fingerprintID) {
		rw.WriteHeader(http.StatusForbidden)
		_, _ = rw.Write([]byte("403 Forbidden: blocked by protector-mirror"))
		go p.notifyBlockedWithMeta(fingerprintID, clientIP, "blocklist", "", req.Method, req.URL.RequestURI(), time.Now().UTC().Format(time.RFC3339Nano))
		return
	}

	// 4b. Check IP blocklist (additive) — blocks entire IP regardless of FP status.
	if p.ipBlocklist.IsBlocked(clientIP) {
		rw.WriteHeader(http.StatusForbidden)
		_, _ = rw.Write([]byte("403 Forbidden: blocked by protector-mirror (IP)"))
		go p.notifyBlockedWithMeta(fingerprintID, clientIP, "ip_block", "", req.Method, req.URL.RequestURI(), time.Now().UTC().Format(time.RFC3339Nano))
		return
	}

	// 5. Wrap ResponseWriter to capture status code
	sc := &statusCapture{ResponseWriter: rw, statusCode: 200}

	// 6. Forward to next handler (WordPress)
	p.next.ServeHTTP(sc, req)

	// 7. Build and enqueue event payload.
	p.enqueueEvent(p.buildEventPayload(req, clientIP, fingerprintID, sc.statusCode, ""))
}

func (p *ProtectorMirror) handlePrefilterHit(req *http.Request, clientIP, fingerprintID string, decision prefilterDecision, timestamp string) {
	if !p.config.SyncToCollectorOnPrefilterHit {
		return
	}

	p.notifyBlockedWithMeta(
		fingerprintID,
		clientIP,
		"prefilter",
		decision.Rule,
		req.Method,
		req.URL.RequestURI(),
		timestamp,
	)

	if p.config.EmitSyntheticEventOnPrefilterHit {
		p.enqueueEvent(p.buildEventPayload(req, clientIP, fingerprintID, http.StatusForbidden, timestamp))
	}

	if p.config.AutoBlockFingerprintOnPrefilterHit {
		p.blockFingerprintStatus(fingerprintID, decision)
	}
}

func (p *ProtectorMirror) buildEventPayload(req *http.Request, clientIP, fingerprintID string, statusCode int, timestamp string) eventPayload {
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	return eventPayload{
		Timestamp: timestamp,
		ClientIP:  clientIP,
		Method:    req.Method,
		URL:       req.URL.RequestURI(),
		Headers: map[string]string{
			"User-Agent":         req.Header.Get("User-Agent"),
			"Accept":             req.Header.Get("Accept"),
			"Accept-Language":    req.Header.Get("Accept-Language"),
			"Accept-Encoding":    req.Header.Get("Accept-Encoding"),
			"Sec-Ch-Ua":          req.Header.Get("Sec-Ch-Ua"),
			"Sec-Ch-Ua-Mobile":   req.Header.Get("Sec-Ch-Ua-Mobile"),
			"Sec-Ch-Ua-Platform": req.Header.Get("Sec-Ch-Ua-Platform"),
		},
		StatusCode:    statusCode,
		FingerprintID: fingerprintID,
	}
}

func (p *ProtectorMirror) enqueueEvent(evt eventPayload) {
	payload, err := json.Marshal(evt)
	if err != nil {
		log.Printf("[protector-mirror] failed to marshal event: %v", err)
		return
	}

	select {
	case p.eventCh <- payload:
		// sent
	default:
		log.Printf("[protector-mirror] event channel full, dropping event for %s", evt.FingerprintID)
	}
}

// notifyBlocked sends a fire-and-forget POST to the Collector's /blocked-event
// endpoint. Intended to be called as a goroutine. Errors are logged but never
// propagated. Uses the shared httpClient (goroutine-safe).
func (p *ProtectorMirror) notifyBlocked(fingerprintID, clientIP string) {
	p.notifyBlockedWithMeta(fingerprintID, clientIP, "blocklist", "", "", "", "")
}

func (p *ProtectorMirror) notifyBlockedWithMeta(fingerprintID, clientIP, blockReason, precheckRule, method, requestURL, timestamp string) {
	payload, err := json.Marshal(blockedEventPayload{
		FingerprintID: fingerprintID,
		ClientIP:      clientIP,
		BlockReason:   blockReason,
		PrecheckRule:  precheckRule,
		Method:        method,
		URL:           requestURL,
		Timestamp:     timestamp,
	})
	if err != nil {
		log.Printf("[protector-mirror] failed to marshal blocked event: %v", err)
		return
	}

	url := p.config.CollectorURL + "/blocked-event"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		log.Printf("[protector-mirror] blocked-event request create error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", p.config.APIKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		log.Printf("[protector-mirror] blocked-event dispatch error: %v", err)
		return
	}
	resp.Body.Close()
}

func (p *ProtectorMirror) blockFingerprintStatus(fingerprintID string, decision prefilterDecision) {
	payload, err := json.Marshal(statusUpdatePayload{
		Status:   "blocked",
		Actor:    "plugin-prefilter",
		Reason:   "Prefilter rule hit",
		RuleName: decision.Rule,
	})
	if err != nil {
		log.Printf("[protector-mirror] failed to marshal status update payload: %v", err)
		return
	}

	requestURL := strings.TrimSuffix(p.config.CollectorURL, "/") + "/users/" + fingerprintID + "/status"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, requestURL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("[protector-mirror] status update request create error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", p.config.APIKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		log.Printf("[protector-mirror] status update dispatch error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[protector-mirror] status update returned non-success status: %d", resp.StatusCode)
	}
}

// dispatchLoop reads events from the channel and POSTs them to the Collector.
func (p *ProtectorMirror) dispatchLoop() {
	client := &http.Client{Timeout: 2 * time.Second}
	url := p.config.CollectorURL + "/events"

	for payload := range p.eventCh {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			log.Printf("[protector-mirror] dispatch request create error: %v", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", p.config.APIKey)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[protector-mirror] dispatch error: %v", err)
			continue
		}
		resp.Body.Close()
	}
}

// resolveClientIP extracts the client IP from X-Forwarded-For (first entry)
// with fallback to RemoteAddr (port stripped).
func resolveClientIP(req *http.Request, trustedProxyNets []*net.IPNet) string {
	remoteIP := parseRemoteAddrIP(req.RemoteAddr)
	if remoteIP == nil {
		return strings.TrimSpace(req.RemoteAddr)
	}

	if !isTrustedProxy(remoteIP, trustedProxyNets) {
		return remoteIP.String()
	}

	if xRealIP := parseHeaderIP(req.Header.Get("X-Real-IP")); xRealIP != nil {
		return xRealIP.String()
	}

	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		if xffIP := parseHeaderIP(parts[0]); xffIP != nil {
			return xffIP.String()
		}
	}

	return remoteIP.String()
}

func parseTrustedProxyCIDRs(cidrStrings []string) ([]*net.IPNet, error) {
	trusted := make([]*net.IPNet, 0, len(cidrStrings))
	for _, cidr := range cidrStrings {
		normalized := strings.TrimSpace(cidr)
		if normalized == "" {
			continue
		}
		_, network, err := net.ParseCIDR(normalized)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", normalized, err)
		}
		trusted = append(trusted, network)
	}
	return trusted, nil
}

func parseRemoteAddrIP(remoteAddr string) net.IP {
	trimmed := strings.TrimSpace(remoteAddr)
	if trimmed == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(trimmed)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(trimmed)
}

func parseHeaderIP(value string) net.IP {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return net.ParseIP(trimmed)
}

func isTrustedProxy(remoteIP net.IP, trustedProxyNets []*net.IPNet) bool {
	if remoteIP == nil {
		return false
	}
	for _, network := range trustedProxyNets {
		if network.Contains(remoteIP) {
			return true
		}
	}
	return false
}

// statusCapture wraps http.ResponseWriter to capture the response status code.
type statusCapture struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// WriteHeader captures the status code before forwarding.
func (sc *statusCapture) WriteHeader(code int) {
	if !sc.written {
		sc.statusCode = code
		sc.written = true
	}
	sc.ResponseWriter.WriteHeader(code)
}

// Write ensures the default status code (200) is recorded if WriteHeader wasn't called.
func (sc *statusCapture) Write(b []byte) (int, error) {
	if !sc.written {
		sc.written = true
		// statusCode stays at 200 (default)
	}
	return sc.ResponseWriter.Write(b)
}

// Flush implements http.Flusher for streaming responses.
func (sc *statusCapture) Flush() {
	if f, ok := sc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker for websocket upgrades.
func (sc *statusCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := sc.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
	}
	return h.Hijack()
}

// Push implements http.Pusher for HTTP/2 server push.
func (sc *statusCapture) Push(target string, opts *http.PushOptions) error {
	p, ok := sc.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return p.Push(target, opts)
}

// CloseNotify implements http.CloseNotifier for compatibility.
func (sc *statusCapture) CloseNotify() <-chan bool {
	if c, ok := sc.ResponseWriter.(http.CloseNotifier); ok {
		return c.CloseNotify()
	}
	ch := make(chan bool)
	return ch
}
