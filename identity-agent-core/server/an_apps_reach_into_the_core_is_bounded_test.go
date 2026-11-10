package server

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"identity-agent-core/limits"
)

// An app's back end that asks past its rate is turned away before anything is
// done for it, and told when to try again; other apps and a person's own device
// are not held back by it.
func TestAnAppPastItsRateIsRefusedWithAWait(t *testing.T) {
	w := newAnAppWorld(t)
	l := limits.Defaults()
	l.RateBurst, l.RatePerSecond = 3, 0.001
	w.cw.s.SetLimits(l)
	key := newBrowsersKey(t)
	w.signedIn(t, "Eann", key, time.Hour)

	for i := 0; i < 3; i++ {
		if rec := w.say(t, aSpokenRequest{who: "Eann", key: key, words: "hi", conversation: "c1"}); rec.Code != http.StatusOK {
			t.Fatalf("request %d within the rate was refused: %d %s", i+1, rec.Code, rec.Body)
		}
	}
	served := *w.served
	rec := w.say(t, aSpokenRequest{who: "Eann", key: key, words: "hi", conversation: "c1"})
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "too many requests") || *w.served != served {
		t.Fatalf("a request past the rate got %d %s, want 429", rec.Code, rec.Body)
	}
	if secs, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || secs < 1 {
		t.Fatalf("a refused rate must say when to try again: Retry-After %q", rec.Header().Get("Retry-After"))
	}
	if err := w.cw.s.holdAppToItsRate("another app"); err != nil {
		t.Fatalf("another app was held back: %v", err)
	}
	err := w.cw.s.holdAppToItsRate("chat")
	if wait, ok := TheAppIsOverItsRate(err); !ok || wait < l.BackoffStart {
		t.Fatalf("got %v, wait %v", err, wait)
	}
	if err := w.cw.s.holdAppToItsRate(""); err != nil {
		t.Fatalf("a machine bound to no app was held to an app's rate: %v", err)
	}
}

// Limits set with only some fields, and none at all, never give an app a rate of
// nothing or a queue that refuses every message, however they were passed in.
func TestPartFilledLimitsNeverMakeARateOfNothing(t *testing.T) {
	for name, l := range map[string]limits.Limits{
		"zero":     {},
		"queue":    {QueueMessages: 5},
		"negative": {RatePerSecond: -1, RateBurst: -3},
	} {
		s := &CoreServer{DataDir: t.TempDir()}
		s.SetLimits(l)
		got := s.AppLimits()
		if got.RatePerSecond <= 0 || got.RateBurst <= 0 || got.QueueBytes <= 0 || got.QueueSharePercent <= 0 || got.QueueMaxAge <= 0 {
			t.Fatalf("%s: %+v", name, got)
		}
		if err := s.holdAppToItsRate("chat"); err != nil {
			t.Fatalf("%s: the first request of an app was refused: %v", name, err)
		}
	}
	// A server never given limits serves the defaults too.
	if got := (&CoreServer{}).AppLimits(); got != limits.Defaults() {
		t.Fatalf("%+v", got)
	}
}
