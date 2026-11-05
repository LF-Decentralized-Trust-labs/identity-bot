package server

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"identity-agent-core/store"
)

func storeRecord(aid string, kel []map[string]interface{}) store.ContactKELRecord {
	return store.ContactKELRecord{AID: aid, KEL: kel, KelVerified: true}
}

// The key log a check caught up from the witnesses is kept on the contact
// record, so the next check needs no catch-up and the agent's own view of the
// issuer is no longer stale. It is kept only when it carries on from the log
// held.

// countingKeyLogReads stands in front of the witness and counts the requests
// that are not for the registry log: the reads of the key log a catch-up makes.
func countingKeyLogReads(t *testing.T, real string) (string, *int32) {
	t.Helper()
	target, _ := url.Parse(real)
	proxy := httputil.NewSingleHostReverseProxy(target)
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/witness/tel/") {
			atomic.AddInt32(&n, 1)
		}
		proxy.ServeHTTP(rw, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &n
}

func TestASecondCheckNeedsNoCatchUpBecauseTheCaughtUpKeyLogWasKept(t *testing.T) {
	w, iss, _, _ := aWorldWhereTheVerifierIsBehind(t, true)
	stale := len(w.kel)
	real := w.base
	var reads *int32
	w.base, reads = countingKeyLogReads(t, real)
	pointTheBootstrapPoolAt(t, w.bob.witnessKey, w.base)

	s := agentWithNoIdentity(t)
	if err := s.DataStore.SaveContactKEL(storeRecord(w.c.aid, w.kel)); err != nil {
		t.Fatal(err)
	}

	_, _, kel := s.issuanceLogForVerification(iss.AcdcBody, s.issuerLogForVerification(w.c.aid))
	if len(kel) <= stale {
		t.Fatalf("the first check did not catch up: %d events, held %d", len(kel), stale)
	}
	if atomic.LoadInt32(reads) == 0 {
		t.Fatal("the first check read no key log from the witness, so there was nothing kept to prove")
	}
	held, err := s.DataStore.GetContactKEL(w.c.aid)
	if err != nil || held == nil || !held.KelVerified || len(held.KEL) != len(kel) {
		t.Fatalf("the caught-up key log was not kept on the contact record: %+v err=%v", held, err)
	}

	before := atomic.LoadInt32(reads)
	_, dup, again := s.issuanceLogForVerification(iss.AcdcBody, s.issuerLogForVerification(w.c.aid))
	if dup != nil || len(again) != len(kel) {
		t.Fatalf("the second check did not see the kept log: dup=%v events=%d", dup, len(again))
	}
	if got := atomic.LoadInt32(reads); got != before {
		t.Fatalf("the second check read the key log from the witness again (%d reads): it caught up a second time", got-before)
	}
}

func TestAForkedKeyLogIsNotKept(t *testing.T) {
	w, iss, _, _ := aWorldWhereTheVerifierIsBehind(t, true)
	s := agentWithNoIdentity(t)
	held := w.kel
	if err := s.DataStore.SaveContactKEL(storeRecord(w.c.aid, held)); err != nil {
		t.Fatal(err)
	}
	pointTheBootstrapPoolAt(t, w.bob.witnessKey, w.base)
	_, _, caughtUp := s.issuanceLogForVerification(iss.AcdcBody, held)
	if len(caughtUp) <= len(held) {
		t.Fatal("setup: the check did not catch up")
	}
	// A longer log that differs from the held one in an event it already holds.
	fork := append([]map[string]interface{}{}, caughtUp...)
	altered := map[string]interface{}{}
	for k, v := range fork[len(held)-1] {
		altered[k] = v
	}
	altered["raw_bytes_b64"] = "AAAA" + altered["raw_bytes_b64"].(string)
	fork[len(held)-1] = altered

	// Put the held log back, then offer the fork.
	if err := s.DataStore.SaveContactKEL(storeRecord(w.c.aid, held)); err != nil {
		t.Fatal(err)
	}
	if s.keepCaughtUpKeyLog(w.c.aid, fork) {
		t.Fatal("a log that does not carry on from the held one was kept")
	}
	got, _ := s.DataStore.GetContactKEL(w.c.aid)
	if got == nil || len(got.KEL) != len(held) {
		t.Fatalf("the held record changed: %+v", got)
	}
	// And a shorter or equal one is not a step forward either.
	if s.keepCaughtUpKeyLog(w.c.aid, held) {
		t.Fatal("a log that adds nothing was kept")
	}
	// The honest extension is kept.
	if !s.keepCaughtUpKeyLog(w.c.aid, caughtUp) {
		t.Fatal("the honest extension was not kept")
	}
}
