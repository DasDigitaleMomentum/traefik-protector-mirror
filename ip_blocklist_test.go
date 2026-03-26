package traefik_protector_mirror

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestIPBlocklistRefreshSendsAPIKeyHeaderAndQuery(t *testing.T) {
	var gotHeader, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-API-Key")
		gotQuery = r.URL.Query().Get("apiKey")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"blocked":["1.2.3.4"]}`))
	}))
	defer srv.Close()

	b := &IPBlocklist{collectorURL: srv.URL, apiKey: "dev-key", blocked: map[string]bool{}}
	b.refresh()

	if gotHeader != "dev-key" {
		t.Fatalf("expected X-API-Key header, got %q", gotHeader)
	}
	if gotQuery != "dev-key" {
		t.Fatalf("expected apiKey query, got %q", gotQuery)
	}
	if !b.IsBlocked("1.2.3.4") {
		t.Fatal("expected 1.2.3.4 blocked")
	}
}

func TestNewIPBlocklistReusesInstanceForSameConfig(t *testing.T) {
	b1 := NewIPBlocklist("http://127.0.0.1:0", 5, "dev-key")
	b2 := NewIPBlocklist("http://127.0.0.1:0", 5, "dev-key")
	if b1 != b2 {
		t.Fatal("expected NewIPBlocklist to reuse existing instance for identical config")
	}
}

func TestNewIPBlocklistHandlesNonPositiveRefreshInterval(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("expected no panic for non-positive refresh interval, got %v", r)
		}
	}()

	_ = NewIPBlocklist("http://127.0.0.1:0", 0, "dev-key")
	_ = NewIPBlocklist("http://127.0.0.1:0", -1, "dev-key")
}

func TestNewIPBlocklistSharedInstanceRefreshesOnceOnInit(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"blocked":[]}`))
	}))
	defer srv.Close()

	_ = NewIPBlocklist(srv.URL, 60, "shared-key")
	_ = NewIPBlocklist(srv.URL, 60, "shared-key")

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 initial refresh call for shared instance, got %d", got)
	}
}
