package server

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
	"identity-agent-core/limits"
	"identity-agent-core/mediation"
	"identity-agent-core/trail"
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

// The delivery queue is the one in the data directory: a restarted server has
// what the last one accepted.
func TestTheDeliveryQueueIsKeptInTheDataDirectoryAcrossARestart(t *testing.T) {
	dir := t.TempDir()
	s1 := &CoreServer{DataDir: dir}
	q, err := s1.DeliveryQueue(anEmptyTrail())
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(mediation.Message{ID: "m1", Conversation: "c", Sender: "s", Recipient: "r", Sealed: []byte("sealed")}); err != nil {
		t.Fatal(err)
	}
	s2 := &CoreServer{DataDir: dir}
	q2, err := s2.DeliveryQueue(anEmptyTrail())
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
		q, err := s.DeliveryQueue(anEmptyTrail())
		if err != nil {
			t.Fatal(err)
		}
		if err := q.Enqueue(mediation.Message{ID: "m", Conversation: "c", Sender: "s", Recipient: "r", Sealed: []byte("x")}); err != nil {
			t.Fatalf("%s: the queue refused a first message: %v", name, err)
		}
	}
	// A server never given limits serves the defaults too.
	if got := (&CoreServer{}).AppLimits(); got != limits.Defaults() {
		t.Fatalf("%+v", got)
	}
}

func anEmptyTrail() *trail.Trail {
	return trail.New(permissiveRoster{}, &keepingApp{}, trail.Options{Countersign: func(agentmessage.Record) (*didcomm.Envelope, error) { return nil, nil }})
}

// A queue is not given without the trail the core marks an expired delivery in,
// so nothing can be held that the core cannot expire (ADR-069).
func TestTheDeliveryQueueIsNotGivenWithoutATrail(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	if q, err := s.DeliveryQueue(nil); err == nil || q != nil {
		t.Fatalf("a queue was given with no trail: %v %v", q, err)
	}
}

// Two add-ons each name their own trail; a message past its age is marked in the
// trail that keeps its conversation, and one that no trail keeps is left held.
func TestEachAddonsExpiredMessageIsMarkedInItsOwnTrail(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	l := limits.Defaults()
	l.QueueMaxAge = 20 * time.Millisecond
	s.SetLimits(l)
	a, b := anEmptyTrail(), anEmptyTrail()
	q, err := s.DeliveryQueue(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeliveryQueue(b); err != nil {
		t.Fatal(err)
	}
	if err := b.Open("cb", "Eann", false); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(mediation.Message{ID: trail.QueueID("cb", "e1"), Conversation: "cb", Sender: "s", Recipient: "r", Sealed: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(mediation.Message{ID: trail.QueueID("nobody", "e1"), Conversation: "nobody", Sender: "s", Recipient: "r", Sealed: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	s.refuseExpiredDeliveries()
	if q.Len() != 1 || len(q.Held("r")) != 1 || q.Held("r")[0].Conversation != "nobody" {
		t.Fatalf("the unowned message must stay held and the owned one go: %d", q.Len())
	}
}
