package protector_mirror

import (
	"net/http"
	"net/http/httptest"
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
