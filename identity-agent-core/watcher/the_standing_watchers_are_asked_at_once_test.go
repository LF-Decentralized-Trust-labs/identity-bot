package watcher

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Every standing watcher is asked at the same time, so the check waits for the
// slowest one and not for all of them in turn.
//
// Fails when askStanding goes back to asking one watcher after another.
func TestTheStandingWatchersAreAskedAtOnce(t *testing.T) {
	const slow = 400 * time.Millisecond
	var urls []string
	for i := 0; i < 4; i++ {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(slow)
			http.Error(w, "not today", http.StatusServiceUnavailable)
		}))
		t.Cleanup(srv.Close)
		urls = append(urls, srv.URL)
	}
	ws := serviceAsking(t, newTestWatcherKey(1), urls...)
	start := time.Now()
	got := ws.askStanding(t.Context(), "EAlice", 0, "Edigest", &VerifyKelResult{})
	if len(got) != 4 {
		t.Fatalf("%d answers, want one per watcher", len(got))
	}
	for i, a := range got {
		if a.w.URL != urls[i] || a.outcome != "unavailable" {
			t.Fatalf("answer %d is %q from %s, want unavailable from %s (in the order listed)", i, a.outcome, a.w.URL, urls[i])
		}
	}
	if took := time.Since(start); took > 2*slow {
		t.Fatalf("four watchers that each take %v took %v together: they were asked one after another", slow, took)
	}
}
