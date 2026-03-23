package protector_mirror

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
