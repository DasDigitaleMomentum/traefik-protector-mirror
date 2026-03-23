// Package traefik_protector_mirror is a Traefik middleware plugin that intercepts
// HTTP requests, computes user fingerprints, enforces a blocklist, and
// asynchronously forwards request events to the Collector service.
package traefik_protector_mirror

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Config holds the plugin configuration from Traefik dynamic config.
type Config struct {
	CollectorURL        string `json:"collectorURL"`
	BlocklistRefreshSec int    `json:"blocklistRefreshSec"`
	APIKey              string `json:"apiKey"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		CollectorURL:        "http://collector:8081",
		BlocklistRefreshSec: 5,
		APIKey:              "",
	}
}

// ProtectorMirror is the middleware struct.
type ProtectorMirror struct {
	next        http.Handler
	name        string
	config      *Config
	blocklist   *Blocklist
	ipBlocklist *IPBlocklist
	eventCh     chan []byte
	httpClient  *http.Client
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

// New creates a new ProtectorMirror middleware instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	log.Printf("[protector-mirror] initializing plugin: collector=%s refreshSec=%d", config.CollectorURL, config.BlocklistRefreshSec)

	p := &ProtectorMirror{
		next:       next,
		name:       name,
		config:     config,
		eventCh:    make(chan []byte, 256),
		httpClient: &http.Client{Timeout: 2 * time.Second},
	}

	// Start blocklist refresh
	p.blocklist = NewBlocklist(config.CollectorURL, config.BlocklistRefreshSec, config.APIKey)

	// Start IP blocklist refresh
	p.ipBlocklist = NewIPBlocklist(config.CollectorURL, config.BlocklistRefreshSec, config.APIKey)

	// Start async event dispatcher
	go p.dispatchLoop()

	return p, nil
}

// ServeHTTP is the middleware handler.
func (p *ProtectorMirror) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// 1. Resolve client IP
	clientIP := resolveClientIP(req)

	// 2. Compute fingerprint ID
	fingerprintID := computeFingerprint(clientIP, req.Header)

	// 3. Check blocklist — enforcement boundary.
	// Only the "blocked" status triggers HTTP 403. Statuses "sandboxed" and
	// "throttled" are accepted by the Collector/API but have NO effect at the
	// plugin layer — they pass through like "active".
	// See collector/handler/status.go for the full status model.
	if p.blocklist.IsBlocked(fingerprintID) {
		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte("403 Forbidden: blocked by protector-mirror"))
		go p.notifyBlocked(fingerprintID, clientIP)
		return
	}

	// 3b. Check IP blocklist (additive) — blocks entire IP regardless of FP status.
	if p.ipBlocklist.IsBlocked(clientIP) {
		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte("403 Forbidden: blocked by protector-mirror (IP)"))
		go p.notifyBlocked(fingerprintID, clientIP)
		return
	}

	// 4. Wrap ResponseWriter to capture status code
	sc := &statusCapture{ResponseWriter: rw, statusCode: 200}

	// 5. Forward to next handler (WordPress)
	p.next.ServeHTTP(sc, req)

	// 6. Build event payload
	evt := eventPayload{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		ClientIP:  clientIP,
		Method:    req.Method,
		URL:       req.URL.RequestURI(),
		Headers: map[string]string{
			"User-Agent":      req.Header.Get("User-Agent"),
			"Accept":          req.Header.Get("Accept"),
			"Accept-Language": req.Header.Get("Accept-Language"),
			"Accept-Encoding": req.Header.Get("Accept-Encoding"),
		},
		StatusCode:    sc.statusCode,
		FingerprintID: fingerprintID,
	}

	payload, err := json.Marshal(evt)
	if err != nil {
		log.Printf("[protector-mirror] failed to marshal event: %v", err)
		return
	}

	// 7. Non-blocking send to event channel
	select {
	case p.eventCh <- payload:
		// sent
	default:
		log.Printf("[protector-mirror] event channel full, dropping event for %s", fingerprintID)
	}
}

// notifyBlocked sends a fire-and-forget POST to the Collector's /blocked-event
// endpoint. Intended to be called as a goroutine. Errors are logged but never
// propagated. Uses the shared httpClient (goroutine-safe).
func (p *ProtectorMirror) notifyBlocked(fingerprintID, clientIP string) {
	payload, err := json.Marshal(map[string]string{
		"fingerprint_id": fingerprintID,
		"client_ip":      clientIP,
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
func resolveClientIP(req *http.Request) string {
	// Try X-Forwarded-For first
	xff := req.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take first entry (may have multiple comma-separated)
		parts := strings.SplitN(xff, ",", 2)
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return ip
		}
	}

	// Fallback: RemoteAddr (strip port)
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
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
