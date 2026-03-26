package traefik_protector_mirror

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDispatchLoopSetsAPIKeyHeader(t *testing.T) {
	var got string
	done := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusAccepted)
		done <- struct{}{}
	}))
	defer srv.Close()

	p := &ProtectorMirror{config: &Config{CollectorURL: srv.URL, APIKey: "dev-key"}, eventCh: make(chan []byte, 1)}
	go p.dispatchLoop()
	p.eventCh <- []byte(`{"timestamp":"x","client_ip":"1.2.3.4","method":"GET","url":"/","status_code":200,"fingerprint_id":"fp"}`)
	close(p.eventCh)

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for dispatch request")
	}
	_ = context.Background()
	if got != "dev-key" {
		t.Fatalf("expected X-API-Key dev-key, got %q", got)
	}
}

func TestNotifyBlockedSetsAPIKeyHeader(t *testing.T) {
	var got string
	done := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-API-Key")
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		done <- struct{}{}
	}))
	defer srv.Close()

	p := &ProtectorMirror{config: &Config{CollectorURL: srv.URL, APIKey: "dev-key"}, httpClient: &http.Client{}}
	p.notifyBlocked("fp", "1.2.3.4")
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for blocked-event request")
	}

	if got != "dev-key" {
		t.Fatalf("expected X-API-Key dev-key, got %q", got)
	}
}

func TestServeHTTP_PrefilterEnforce_SyncsCollectorAndReturns403(t *testing.T) {
	type statusCall struct {
		path string
		body []byte
	}

	blockedCh := make(chan []byte, 1)
	statusCh := make(chan statusCall, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/blocklist" || r.URL.Path == "/ip-blocklist":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"blocked":[]}`))
		case r.URL.Path == "/blocked-event":
			body, _ := io.ReadAll(r.Body)
			blockedCh <- body
			w.WriteHeader(http.StatusAccepted)
		case strings.HasPrefix(r.URL.Path, "/users/") && strings.HasSuffix(r.URL.Path, "/status"):
			body, _ := io.ReadAll(r.Body)
			statusCh <- statusCall{path: r.URL.Path, body: body}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := &ProtectorMirror{
		next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}),
		config: &Config{
			CollectorURL:                       srv.URL,
			APIKey:                             "dev-key",
			PrefilterEnabled:                   true,
			PrefilterMode:                      "enforce",
			PrefilterFailMode:                  "open",
			PrefilterRules:                     defaultPrefilterRules(),
			SyncToCollectorOnPrefilterHit:      true,
			EmitSyntheticEventOnPrefilterHit:   true,
			AutoBlockFingerprintOnPrefilterHit: true,
		},
		httpClient:  srv.Client(),
		eventCh:     make(chan []byte, 4),
		blocklist:   &Blocklist{blocked: map[string]bool{}},
		ipBlocklist: &IPBlocklist{blocked: map[string]bool{}},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/wp-config.php", nil)
	req.RemoteAddr = "203.0.113.10:3456"
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rr.Code)
	}

	select {
	case eventBody := <-p.eventCh:
		var evt map[string]any
		if err := json.Unmarshal(eventBody, &evt); err != nil {
			t.Fatalf("failed to parse synthetic event JSON: %v", err)
		}
		if got := int(evt["status_code"].(float64)); got != http.StatusForbidden {
			t.Fatalf("expected synthetic status_code 403, got %d", got)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for synthetic 403 event")
	}

	select {
	case body := <-blockedCh:
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("failed to parse blocked-event JSON: %v", err)
		}
		if got := payload["block_reason"]; got != "prefilter" {
			t.Fatalf("expected block_reason=prefilter, got %v", got)
		}
		if got := payload["precheck_rule"]; got != "denied_path" {
			t.Fatalf("expected precheck_rule=denied_path, got %v", got)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for blocked-event sync")
	}

	select {
	case call := <-statusCh:
		if !strings.HasPrefix(call.path, "/users/") || !strings.HasSuffix(call.path, "/status") {
			t.Fatalf("unexpected status update path: %s", call.path)
		}
		var payload map[string]any
		if err := json.Unmarshal(call.body, &payload); err != nil {
			t.Fatalf("failed to parse status update JSON: %v", err)
		}
		if got := payload["status"]; got != "blocked" {
			t.Fatalf("expected status=blocked, got %v", got)
		}
		if got := payload["actor"]; got != "plugin-prefilter" {
			t.Fatalf("expected actor=plugin-prefilter, got %v", got)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for status sync")
	}
}

func TestServeHTTP_PrefilterDetect_DoesNotBlockAndStillEnqueuesEvent(t *testing.T) {
	blockedCh := make(chan struct{}, 1)
	statusCh := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/blocklist" || r.URL.Path == "/ip-blocklist":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"blocked":[]}`))
		case r.URL.Path == "/blocked-event":
			blockedCh <- struct{}{}
			w.WriteHeader(http.StatusAccepted)
		case strings.HasPrefix(r.URL.Path, "/users/") && strings.HasSuffix(r.URL.Path, "/status"):
			statusCh <- struct{}{}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := &ProtectorMirror{
		next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
		config: &Config{
			CollectorURL:                       srv.URL,
			APIKey:                             "dev-key",
			PrefilterEnabled:                   true,
			PrefilterMode:                      "detect",
			PrefilterFailMode:                  "open",
			PrefilterRules:                     defaultPrefilterRules(),
			SyncToCollectorOnPrefilterHit:      true,
			EmitSyntheticEventOnPrefilterHit:   true,
			AutoBlockFingerprintOnPrefilterHit: true,
		},
		httpClient:  srv.Client(),
		eventCh:     make(chan []byte, 2),
		blocklist:   &Blocklist{blocked: map[string]bool{}},
		ipBlocklist: &IPBlocklist{blocked: map[string]bool{}},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/wp-config.php", nil)
	req.RemoteAddr = "203.0.113.20:3456"
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", rr.Code)
	}

	select {
	case <-blockedCh:
		t.Fatal("did not expect blocked-event sync in detect mode")
	case <-statusCh:
		t.Fatal("did not expect status sync in detect mode")
	case <-time.After(150 * time.Millisecond):
	}

	select {
	case eventBody := <-p.eventCh:
		var evt map[string]any
		if err := json.Unmarshal(eventBody, &evt); err != nil {
			t.Fatalf("failed to parse event JSON: %v", err)
		}
		if got := int(evt["status_code"].(float64)); got != http.StatusNoContent {
			t.Fatalf("expected status_code 204, got %d", got)
		}
	default:
		t.Fatal("expected event to be enqueued in detect mode")
	}
}

func TestServeHTTP_PrefilterUsesDynamicRulesFromStore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/blocklist", "/ip-blocklist":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"blocked":[]}`))
		case "/prefilter-config":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"rules":{"uriLengthMax":2048,"queryLengthMax":2048,"queryParamCountMax":32,"headerValueLengthMax":4096,"deniedPathPrefixes":["/dynamic-block"],"deniedUserAgentSubstrings":[],"deniedCountries":[]},"version":"v1","updatedAt":"2026-03-26T12:00:00Z"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := CreateConfig()
	cfg.CollectorURL = srv.URL
	cfg.APIKey = "dev-key"
	cfg.BlocklistRefreshSec = 3600
	cfg.PrefilterRefreshSec = 3600
	cfg.PrefilterEnabled = true
	cfg.PrefilterMode = "enforce"
	cfg.PrefilterRules = PrefilterRules{
		URILengthMax:         65535,
		QueryLengthMax:       65535,
		QueryParamCountMax:   256,
		HeaderValueLengthMax: 65535,
		DeniedPathPrefixes:   []string{},
		DeniedUserAgentSubs:  []string{},
	}
	cfg.SyncToCollectorOnPrefilterHit = false
	cfg.EmitSyntheticEventOnPrefilterHit = false
	cfg.AutoBlockFingerprintOnPrefilterHit = false

	h, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), cfg, "test")
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/dynamic-block/now", nil)
	req.RemoteAddr = "203.0.113.30:3456"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected dynamic prefilter to block with 403, got %d", rr.Code)
	}
}

func TestServeHTTP_PrefilterLegacyFallbackUsesStaticRulesWithoutCollectorURL(t *testing.T) {
	p := &ProtectorMirror{
		next: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
		config: &Config{
			CollectorURL:        "",
			APIKey:              "dev-key",
			PrefilterEnabled:    true,
			PrefilterMode:       "enforce",
			PrefilterFailMode:   "open",
			PrefilterRefreshSec: 30,
			PrefilterRules: PrefilterRules{
				URILengthMax:         2048,
				QueryLengthMax:       2048,
				QueryParamCountMax:   32,
				HeaderValueLengthMax: 4096,
				DeniedPathPrefixes:   []string{"/legacy-block"},
				DeniedUserAgentSubs:  []string{},
			},
			SyncToCollectorOnPrefilterHit:      false,
			EmitSyntheticEventOnPrefilterHit:   false,
			AutoBlockFingerprintOnPrefilterHit: false,
		},
		httpClient:  &http.Client{},
		eventCh:     make(chan []byte, 2),
		blocklist:   &Blocklist{blocked: map[string]bool{}},
		ipBlocklist: &IPBlocklist{blocked: map[string]bool{}},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/legacy-block/path", nil)
	req.RemoteAddr = "203.0.113.40:3456"
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected static legacy prefilter to block with 403, got %d", rr.Code)
	}
}

type stubGeoResolver struct {
	country string
	err     error
	calls   int
}

func (s *stubGeoResolver) LookupCountry(_ string) (string, error) {
	s.calls++
	return s.country, s.err
}

func TestEvaluatePrefilter_GeoBlocksDeniedCountry(t *testing.T) {
	cfg := &Config{PrefilterEnabled: true, PrefilterFailMode: "open"}
	rules := defaultPrefilterRules()
	rules.DeniedCountries = []string{"DE"}
	rules.DeniedPathPrefixes = nil

	req := httptest.NewRequest(http.MethodGet, "http://example.com/ok", nil)
	req.Header.Set("User-Agent", "mozilla")
	resolver := &stubGeoResolver{country: "de"}

	decision, err := evaluatePrefilter(cfg, rules, resolver, "203.0.113.10", req)
	if err != nil {
		t.Fatalf("evaluatePrefilter returned error: %v", err)
	}
	if !decision.Matched || decision.Rule != "denied_country" {
		t.Fatalf("expected denied_country match, got %+v", decision)
	}
	if resolver.calls != 1 {
		t.Fatalf("expected resolver to be called once, got %d", resolver.calls)
	}
}

func TestEvaluatePrefilter_GeoAllowsNonDeniedCountry(t *testing.T) {
	cfg := &Config{PrefilterEnabled: true, PrefilterFailMode: "open"}
	rules := defaultPrefilterRules()
	rules.DeniedCountries = []string{"DE"}
	rules.DeniedPathPrefixes = nil

	resolver := &stubGeoResolver{country: "US"}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/ok", nil)
	req.RemoteAddr = "203.0.113.90:1234"
	req.Header.Set("User-Agent", "mozilla")

	decision, err := evaluatePrefilter(cfg, rules, resolver, "203.0.113.90", req)
	if err != nil {
		t.Fatalf("evaluatePrefilter returned error: %v", err)
	}
	if decision.Matched {
		t.Fatalf("expected no geo block match, got %+v", decision)
	}
	if resolver.calls != 1 {
		t.Fatalf("expected resolver to be called once, got %d", resolver.calls)
	}
}

func TestEvaluatePrefilter_GeoFailOpenOnResolverError(t *testing.T) {
	cfg := &Config{PrefilterEnabled: true, PrefilterFailMode: "open"}
	rules := defaultPrefilterRules()
	rules.DeniedCountries = []string{"DE"}
	rules.DeniedPathPrefixes = nil

	resolver := &stubGeoResolver{err: errors.New("timeout")}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/ok", nil)

	decision, err := evaluatePrefilter(cfg, rules, resolver, "203.0.113.11", req)
	if err != nil {
		t.Fatalf("evaluatePrefilter returned error: %v", err)
	}
	if decision.Matched {
		t.Fatalf("expected fail-open to pass request, got %+v", decision)
	}
}

func TestEvaluatePrefilter_GeoFailClosedOnResolverError(t *testing.T) {
	cfg := &Config{PrefilterEnabled: true, PrefilterFailMode: "closed"}
	rules := defaultPrefilterRules()
	rules.DeniedCountries = []string{"DE"}
	rules.DeniedPathPrefixes = nil

	resolver := &stubGeoResolver{err: errors.New("timeout")}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/ok", nil)

	decision, err := evaluatePrefilter(cfg, rules, resolver, "203.0.113.12", req)
	if err != nil {
		t.Fatalf("evaluatePrefilter returned error: %v", err)
	}
	if !decision.Matched || decision.Rule != "denied_country" {
		t.Fatalf("expected fail-closed denied_country match, got %+v", decision)
	}
}

func TestEvaluatePrefilter_BlocksDeniedPathRegex(t *testing.T) {
	cfg := &Config{PrefilterEnabled: true}
	rules := defaultPrefilterRules()
	rules.DeniedPathPrefixes = nil
	rules.DeniedPathRegexes = []string{`^/api/v[0-9]+/admin`}
	prepared, err := prepareRulesForStorage(rules)
	if err != nil {
		t.Fatalf("prepareRulesForStorage returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/v2/admin/panel", nil)
	decision, err := evaluatePrefilter(cfg, prepared, nil, "203.0.113.13", req)
	if err != nil {
		t.Fatalf("evaluatePrefilter returned error: %v", err)
	}
	if !decision.Matched || decision.Rule != "denied_path_regex" {
		t.Fatalf("expected denied_path_regex match, got %+v", decision)
	}
}

func TestResolveClientIP_UsesForwardHeadersForTrustedProxy(t *testing.T) {
	nets, err := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parseTrustedProxyCIDRs returned error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/ok", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	req.Header.Set("X-Real-IP", "203.0.113.100")
	req.Header.Set("X-Forwarded-For", "203.0.113.101")

	got := resolveClientIP(req, nets)
	if got != "203.0.113.100" {
		t.Fatalf("expected trusted proxy to use X-Real-IP, got %q", got)
	}
}

func TestResolveClientIP_IgnoresForwardHeadersForUntrustedProxy(t *testing.T) {
	nets, err := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parseTrustedProxyCIDRs returned error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/ok", nil)
	req.RemoteAddr = "198.51.100.2:2345"
	req.Header.Set("X-Real-IP", "203.0.113.100")
	req.Header.Set("X-Forwarded-For", "203.0.113.101")

	got := resolveClientIP(req, nets)
	if got != "198.51.100.2" {
		t.Fatalf("expected untrusted proxy to fall back to remote addr, got %q", got)
	}
}

type fakeRWWithAllInterfaces struct {
	headers    http.Header
	flushCalls int
	pushCalls  int
	closeCh    chan bool
}

func (f *fakeRWWithAllInterfaces) Header() http.Header {
	if f.headers == nil {
		f.headers = make(http.Header)
	}
	return f.headers
}
func (f *fakeRWWithAllInterfaces) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeRWWithAllInterfaces) WriteHeader(_ int)           {}
func (f *fakeRWWithAllInterfaces) Flush()                      { f.flushCalls++ }
func (f *fakeRWWithAllInterfaces) Push(_ string, _ *http.PushOptions) error {
	f.pushCalls++
	return nil
}
func (f *fakeRWWithAllInterfaces) CloseNotify() <-chan bool {
	if f.closeCh == nil {
		f.closeCh = make(chan bool)
	}
	return f.closeCh
}
func (f *fakeRWWithAllInterfaces) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}

func TestStatusCapture_InterfacePassthrough(t *testing.T) {
	base := &fakeRWWithAllInterfaces{}
	sc := &statusCapture{ResponseWriter: base, statusCode: 200}

	sc.Flush()
	if base.flushCalls != 1 {
		t.Fatalf("expected Flush passthrough call, got %d", base.flushCalls)
	}

	if err := sc.Push("/resource", nil); err != nil {
		t.Fatalf("expected Push passthrough success, got %v", err)
	}
	if base.pushCalls != 1 {
		t.Fatalf("expected Push passthrough call, got %d", base.pushCalls)
	}

	if _, _, err := sc.Hijack(); err != nil {
		t.Fatalf("expected Hijack passthrough success, got %v", err)
	}

	if ch := sc.CloseNotify(); ch == nil {
		t.Fatal("expected CloseNotify channel")
	}
}
