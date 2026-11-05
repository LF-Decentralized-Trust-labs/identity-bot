package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"identity-agent-core/store"
)

func enqueueFor(t *testing.T, s *CoreServer, issuer, kind string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		said := fmt.Sprintf("E%s-%s-%d", issuer, kind, i)
		if err := s.DataStore.EnqueueTELPush(store.TELPush{IssuerAID: issuer, SAID: said, Kind: kind, RawB64: "AAAA"}); err != nil {
			t.Fatal(err)
		}
	}
}

// One issuer with a pass's worth of events waiting, whose witnesses never
// answer, must not keep every other issuer's out of the pass.
func TestOneStuckIssuerDoesNotCrowdOutTheOthersInTheOutbox(t *testing.T) {
	s := agentWithNoIdentity(t)
	enqueueFor(t, s, "ESTUCK", "iss", telPushBatch)
	enqueueFor(t, s, "EOTHER1", "iss", 1)
	enqueueFor(t, s, "EOTHER2", "rev", 1)
	for name, take := range map[string]func() ([]store.TELPush, error){
		"pending": func() ([]store.TELPush, error) { return s.DataStore.PendingTELPushes(telPushBatch) },
		"due": func() ([]store.TELPush, error) {
			return s.DataStore.DueTELPushes(telPushBatch, time.Now().UTC().Format(telPushTime))
		},
	} {
		got, err := take()
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]int{}
		for _, p := range got {
			seen[p.IssuerAID]++
		}
		if len(got) != telPushBatch || seen["EOTHER1"] != 1 || seen["EOTHER2"] != 1 {
			t.Fatalf("%s: a full pass of %d held %v: the issuers that are not stuck were left out", name, len(got), seen)
		}
		if got[0].IssuerAID == "ESTUCK" && got[1].IssuerAID == "ESTUCK" && got[2].IssuerAID == "ESTUCK" {
			t.Fatalf("%s: the stuck issuer's events come before everyone else's", name)
		}
	}
}

func TestAFailedIssuerIsTriedAgainOnlyAfterAGap(t *testing.T) {
	w := newPushWorld(t)
	w.s.telPushRetryGap = nil // the real gaps
	w.contactAt("http://127.0.0.1:1")
	w.issue()
	// (The witnessing worker, kicked by the issuance, makes the first attempt or
	// this does; whichever it is, the other finds the issuer not yet due.)
	var first []store.TELPush
	for i := 0; i < 100; i++ {
		w.s.pushRegistryEvents(context.Background())
		if first = w.pending(); len(first) > 0 && first[0].Attempts >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(first) == 0 || first[0].Attempts < 1 || first[0].NextAttemptAt == "" {
		t.Fatalf("a failed attempt did not set when to try again: %+v", first)
	}
	time.Sleep(200 * time.Millisecond) // let a pass in flight finish
	first = w.pending()
	w.s.pushRegistryEvents(context.Background())
	again := w.pending()
	if again[0].Attempts != first[0].Attempts {
		t.Fatalf("an issuer that failed a moment ago was tried again at once: %d then %d attempts", first[0].Attempts, again[0].Attempts)
	}
	if telPushRetryGap(1) >= telPushRetryGap(4) || telPushRetryGap(40) > telPushRetryMax {
		t.Fatalf("the gap does not grow to a ceiling: %v %v %v", telPushRetryGap(1), telPushRetryGap(4), telPushRetryGap(40))
	}
}

// A revocation that has waited for weeks is still waiting, and is reported.
func TestARevocationIsNeverDroppedHoweverLongItWaitsAndIsReported(t *testing.T) {
	w := newPushWorld(t)
	w.contactAt("http://127.0.0.1:1")
	long := time.Now().Add(-90 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	for _, kind := range []string{"vcp", "iss", "rev"} {
		if err := w.s.DataStore.EnqueueTELPush(store.TELPush{IssuerAID: w.aid, SAID: "E" + kind, Kind: kind, RawB64: "AAAA", CreatedAt: long}); err != nil {
			t.Fatal(err)
		}
	}
	w.s.pushRegistryEvents(context.Background())
	if p := w.pending(); len(p) != 3 {
		t.Fatalf("an event that waited 90 days was dropped: %d of 3 left", len(p))
	}
	waiting, err := w.s.DataStore.WaitingRevocations(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano))
	if err != nil || len(waiting) != 1 || waiting[0].SAID != "Erev" {
		t.Fatalf("the waiting revocation is not found: %v %+v", err, waiting)
	}
	w.s.telAlarm.Lock()
	reported := w.s.telAlarm.said[w.aid+"|Erev"]
	w.s.telAlarm.Unlock()
	if !reported {
		t.Fatal("a revocation that never reached a witness was not reported")
	}
}
