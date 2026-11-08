package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"identity-agent-core/limits"
	"identity-agent-core/mediation"
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
	if rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "too many requests") || *w.served != served {
		t.Fatalf("a request past the rate got %d %s", rec.Code, rec.Body)
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

// The delivery queue is the one in the data directory: a restarted server has
// what the last one accepted.
func TestTheDeliveryQueueIsKeptInTheDataDirectoryAcrossARestart(t *testing.T) {
	dir := t.TempDir()
	s1 := &CoreServer{DataDir: dir}
	q, err := s1.DeliveryQueue()
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(mediation.Message{ID: "m1", Conversation: "c", Sender: "s", Recipient: "r", Sealed: []byte("sealed")}); err != nil {
		t.Fatal(err)
	}
	s2 := &CoreServer{DataDir: dir}
	q2, err := s2.DeliveryQueue()
	if err != nil || q2.Len() != 1 || len(q2.Held("r")) != 1 {
		t.Fatalf("after a restart: %v %v", q2, err)
	}
	// A phone scales its capacity only.
	s3 := &CoreServer{DataDir: dir}
	s3.SetLimits(limits.Defaults().ForPhone())
	if got := s3.AppLimits(); got.QueueMessages != limits.Defaults().QueueMessages/10 || got.ForwardTimeout != limits.Defaults().ForwardTimeout {
		t.Fatalf("%+v", got)
	}
}
