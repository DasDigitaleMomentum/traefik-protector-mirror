package traefik_protector_mirror

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPrefilterConfigRefreshSendsAPIKeyHeaderAndQuery(t *testing.T) {
	var gotHeader, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-API-Key")
		gotQuery = r.URL.Query().Get("apiKey")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"rules":{"uriLengthMax":2048,"queryLengthMax":2048,"queryParamCountMax":32,"headerValueLengthMax":4096,"deniedPathPrefixes":["/foo"],"deniedUserAgentSubstrings":["bar"]},"version":"v1","updatedAt":"2026-03-26T12:00:00Z"}`))
	}))
	defer srv.Close()

	s := &PrefilterConfigStore{collectorURL: srv.URL, apiKey: "dev-key", rules: defaultPrefilterRules()}
	s.refresh()

	if gotHeader != "dev-key" {
		t.Fatalf("expected X-API-Key header, got %q", gotHeader)
	}
	if gotQuery != "dev-key" {
		t.Fatalf("expected apiKey query, got %q", gotQuery)
	}

	rules := s.GetRules()
	if len(rules.DeniedPathPrefixes) != 1 || rules.DeniedPathPrefixes[0] != "/foo" {
		t.Fatalf("expected refreshed denied paths from collector, got %+v", rules.DeniedPathPrefixes)
	}
}

func TestNewPrefilterConfigStoreReusesInstanceForSameConfig(t *testing.T) {
	s1 := NewPrefilterConfigStore("http://127.0.0.1:0", 30, "dev-key", defaultPrefilterRules())
	s2 := NewPrefilterConfigStore("http://127.0.0.1:0", 30, "dev-key", defaultPrefilterRules())
	if s1 != s2 {
		t.Fatal("expected NewPrefilterConfigStore to reuse existing instance for identical config")
	}
}

func TestNewPrefilterConfigStoreHandlesNonPositiveRefreshInterval(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("expected no panic for non-positive refresh interval, got %v", r)
		}
	}()

	_ = NewPrefilterConfigStore("http://127.0.0.1:0", 0, "dev-key", defaultPrefilterRules())
	_ = NewPrefilterConfigStore("http://127.0.0.1:0", -1, "dev-key", defaultPrefilterRules())
}

func TestNewPrefilterConfigStoreSharedInstanceRefreshesOnceOnInit(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"rules":{"uriLengthMax":2048,"queryLengthMax":2048,"queryParamCountMax":32,"headerValueLengthMax":4096,"deniedPathPrefixes":["/.env"],"deniedUserAgentSubstrings":["sqlmap"]},"version":"v1","updatedAt":"2026-03-26T12:00:00Z"}`))
	}))
	defer srv.Close()

	_ = NewPrefilterConfigStore(srv.URL, 60, "shared-key", defaultPrefilterRules())
	_ = NewPrefilterConfigStore(srv.URL, 60, "shared-key", defaultPrefilterRules())

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 initial refresh call for shared instance, got %d", got)
	}
}

func TestPrefilterConfigStoreRefreshKeepsStaleOnError(t *testing.T) {
	var mode atomic.Int32
	mode.Store(0)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode.Load() == 0 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"rules":{"uriLengthMax":2048,"queryLengthMax":2048,"queryParamCountMax":32,"headerValueLengthMax":4096,"deniedPathPrefixes":["/fresh"],"deniedUserAgentSubstrings":[]},"version":"v1","updatedAt":"2026-03-26T12:00:00Z"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := &PrefilterConfigStore{collectorURL: srv.URL, apiKey: "dev-key", rules: defaultPrefilterRules()}
	s.refresh()
	mode.Store(1)
	s.refresh()

	rules := s.GetRules()
	if len(rules.DeniedPathPrefixes) != 1 || rules.DeniedPathPrefixes[0] != "/fresh" {
		t.Fatalf("expected stale rules to stay active after refresh error, got %+v", rules.DeniedPathPrefixes)
	}
}

func TestPrefilterConfigStoreRefreshVersionChangeDetection(t *testing.T) {
	state := int32(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		step := atomic.LoadInt32(&state)
		w.Header().Set("Content-Type", "application/json")
		switch step {
		case 0:
			_, _ = w.Write([]byte(`{"rules":{"uriLengthMax":2048,"queryLengthMax":2048,"queryParamCountMax":32,"headerValueLengthMax":4096,"deniedPathPrefixes":["/v1"],"deniedUserAgentSubstrings":[]},"version":"v1","updatedAt":"2026-03-26T12:00:00Z"}`))
		case 1:
			_, _ = w.Write([]byte(`{"rules":{"uriLengthMax":2048,"queryLengthMax":2048,"queryParamCountMax":32,"headerValueLengthMax":4096,"deniedPathPrefixes":["/v2-ignored"],"deniedUserAgentSubstrings":[]},"version":"v1","updatedAt":"2026-03-26T12:00:01Z"}`))
		default:
			_, _ = w.Write([]byte(`{"rules":{"uriLengthMax":2048,"queryLengthMax":2048,"queryParamCountMax":32,"headerValueLengthMax":4096,"deniedPathPrefixes":["/v3"],"deniedUserAgentSubstrings":[]},"version":"v3","updatedAt":"2026-03-26T12:00:02Z"}`))
		}
	}))
	defer srv.Close()

	s := &PrefilterConfigStore{collectorURL: srv.URL, apiKey: "dev-key", rules: defaultPrefilterRules()}

	s.refresh()
	r1 := s.GetRules()
	if got := firstOrEmpty(r1.DeniedPathPrefixes); got != "/v1" {
		t.Fatalf("expected first refresh to set /v1, got %q", got)
	}

	atomic.StoreInt32(&state, 1)
	s.refresh()
	r2 := s.GetRules()
	if got := firstOrEmpty(r2.DeniedPathPrefixes); got != "/v1" {
		t.Fatalf("expected same-version refresh to keep /v1, got %q", got)
	}

	atomic.StoreInt32(&state, 2)
	s.refresh()
	r3 := s.GetRules()
	if got := firstOrEmpty(r3.DeniedPathPrefixes); got != "/v3" {
		t.Fatalf("expected changed-version refresh to set /v3, got %q", got)
	}
}

func firstOrEmpty(in []string) string {
	if len(in) == 0 {
		return ""
	}
	return in[0]
}

func TestPrefilterConfigStoreRejectsMissingRulesEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"v1","updatedAt":"2026-03-26T12:00:00Z"}`))
	}))
	defer srv.Close()

	fallback := defaultPrefilterRules()
	s := &PrefilterConfigStore{collectorURL: srv.URL, apiKey: "dev-key", rules: fallback}
	s.refresh()

	rules := s.GetRules()
	if fmt.Sprintf("%v", rules.DeniedPathPrefixes) != fmt.Sprintf("%v", fallback.DeniedPathPrefixes) {
		t.Fatalf("expected fallback/stale rules to remain when rules envelope missing")
	}
}
