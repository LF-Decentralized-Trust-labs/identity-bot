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
	// Asked in turn they take watchers*slow (2.4s); at once, about slow. The
	// bound sits well between, so a loaded machine does not fail it.
	const slow = 400 * time.Millisecond
	const watchers = 6
	var urls []string
	for i := 0; i < watchers; i++ {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(slow)
			http.Error(w, "not today", http.StatusServiceUnavailable)
		}))
		t.Cleanup(srv.Close)
		urls = append(urls, srv.URL)
	}
	ws := serviceAsking(t, newTestWatcherKey(1), urls...)
	start := time.Now()
	got := ws.askStanding(t.Context(), "EAlice", 0, "Edigest")
	if len(got) != watchers {
		t.Fatalf("%d answers, want one per watcher", len(got))
	}
	for i, a := range got {
		if a.w.URL != urls[i] || a.outcome != "unavailable" {
			t.Fatalf("answer %d is %q from %s, want unavailable from %s (in the order listed)", i, a.outcome, a.w.URL, urls[i])
		}
	}
	if took := time.Since(start); took > 4*slow {
		t.Fatalf("%d watchers that each take %v took %v together: they were asked one after another", watchers, slow, took)
	}
}
