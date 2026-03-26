package traefik_protector_mirror

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestBlocklistRefreshSendsAPIKeyHeaderAndQuery(t *testing.T) {
	var gotHeader, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-API-Key")
		gotQuery = r.URL.Query().Get("apiKey")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"blocked":["fp1"]}`))
	}))
	defer srv.Close()

	b := &Blocklist{collectorURL: srv.URL, apiKey: "dev-key", blocked: map[string]bool{}}
	b.refresh()

	if gotHeader != "dev-key" {
		t.Fatalf("expected X-API-Key header, got %q", gotHeader)
	}
	if gotQuery != "dev-key" {
		t.Fatalf("expected apiKey query, got %q", gotQuery)
	}
	if !b.IsBlocked("fp1") {
		t.Fatal("expected fp1 blocked")
	}
}

func TestNewBlocklistReusesInstanceForSameConfig(t *testing.T) {
	b1 := NewBlocklist("http://127.0.0.1:0", 5, "dev-key")
	b2 := NewBlocklist("http://127.0.0.1:0", 5, "dev-key")
	if b1 != b2 {
		t.Fatal("expected NewBlocklist to reuse existing instance for identical config")
	}
}

func TestNewBlocklistHandlesNonPositiveRefreshInterval(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("expected no panic for non-positive refresh interval, got %v", r)
		}
	}()

	_ = NewBlocklist("http://127.0.0.1:0", 0, "dev-key")
	_ = NewBlocklist("http://127.0.0.1:0", -1, "dev-key")
}

func TestNewBlocklistSharedInstanceRefreshesOnceOnInit(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"blocked":[]}`))
	}))
	defer srv.Close()

	_ = NewBlocklist(srv.URL, 60, "shared-key")
	_ = NewBlocklist(srv.URL, 60, "shared-key")

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 initial refresh call for shared instance, got %d", got)
	}
}
