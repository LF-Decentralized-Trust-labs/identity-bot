package watcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// repeatContact is a service that has already met EBob, whose hosted watcher
// (served by serving, trusted) holds hostedDigest for him, and which asks one
// contact answering match. It returns what each was asked and the events raised.
type repeatContact struct {
	ws     *Service
	hosted *Service
	asked  *int32
	events *[]string
	kel    []map[string]interface{}
	source string
}

func newRepeatContact(t *testing.T, peerMatches bool) *repeatContact {
	t.Helper()
	k := newTestWatcherKey(9)
	url, hosted := servedBy(t, &k, nil)
	ws := storedService(t)
	ws.L2 = clientTrusting(k)
	_ = setStanding(ws, url)
	var events []string
	ws.OnEvent = func(typ string, _ map[string]interface{}) { events = append(events, typ) }

	var asked int32
	peerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&asked, 1)
		_ = json.NewEncoder(w).Encode(KelCheckResponse{Match: peerMatches})
	}))
	t.Cleanup(peerSrv.Close)
	ws.SignRequest = func(string, string) (string, string, error) { return "Ewatcher", "sig", nil }
	ws.L3.AllowLocal = func(string) bool { return true }
	ws.PeerWatchers = func() []PeerWatcher { return []PeerWatcher{{AID: "EContact", URL: peerSrv.URL}} }
	if err := ws.SetPeerWatchEnabled(true); err != nil {
		t.Fatal(err)
	}

	rc := &repeatContact{
		ws: ws, hosted: hosted, asked: &asked, events: &events, source: peerSrv.URL + "/public/oobi/EBob",
		kel: []map[string]interface{}{{"v": "KERI10JSON000256_", "t": "icp", "i": "EBob", "s": "0"}},
	}
	// The first contact: nothing is held anywhere yet.
	res, err := ws.VerifyKel(context.Background(), VerifyKelInput{AID: "EBob", KEL: rc.kel, SourceType: SourceOOBI, SourceURL: rc.source})
	if err != nil || !res.OK {
		t.Fatalf("first contact: %+v %v", res, err)
	}
	*rc.asked, *rc.events = 0, nil
	return rc
}

func (rc *repeatContact) again(t *testing.T) *VerifyKelResult {
	t.Helper()
	res, err := rc.ws.VerifyKel(context.Background(), VerifyKelInput{AID: "EBob", KEL: rc.kel, SourceType: SourceOOBI, SourceURL: rc.source})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (rc *repeatContact) alerts(t *testing.T) []DuplicityAlert {
	t.Helper()
	a, err := rc.ws.Store.listDuplicityAlerts("EBob")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (rc *repeatContact) sawEvent(name string) bool {
	for _, e := range *rc.events {
		if e == name {
			return true
		}
	}
	return false
}

// A hosted watcher that disagrees with the record this agent holds on a repeat
// contact is escalated whatever a contact says. It is an event for Activity and
// is never stored as a duplicity alert, which would block the next check.
func TestAHostedWatcherThatDisagreesIsEscalatedWhateverAContactSays(t *testing.T) {
	for name, peerMatches := range map[string]bool{"the contact does not match": false, "the contact matches": true} {
		rc := newRepeatContact(t, peerMatches)
		seen(t, rc.hosted, "EBob", 0, "Edifferent")
		res := rc.again(t)
		if !res.OK || res.Blocked {
			t.Fatalf("%s: an escalation blocked: %+v", name, res)
		}
		if res.OverallOutcome != "escalated" {
			t.Fatalf("%s: outcome %q, want escalated", name, res.OverallOutcome)
		}
		if !rc.sawEvent("kel_l3_escalation") {
			t.Fatalf("%s: no escalation was announced: %v", name, *rc.events)
		}
		if a := rc.alerts(t); len(a) != 0 {
			t.Fatalf("%s: the escalation was stored as a duplicity alert: %+v", name, a)
		}
		// The contact was asked and its answer recorded, as context only.
		if *rc.asked != 1 {
			t.Fatalf("%s: the contact was asked %d times, want 1", name, *rc.asked)
		}
		want := "no_match"
		if peerMatches {
			want = "match"
		}
		var l3 string
		for _, o := range res.sourcesQueried {
			if o.Type == "L3" {
				l3 = o.Outcome
			}
		}
		if l3 != want {
			t.Fatalf("%s: the contact's answer recorded as %q, want %q", name, l3, want)
		}
		// Checked again, an escalation still does not block.
		if again := rc.again(t); again.Blocked || len(rc.alerts(t)) != 0 {
			t.Fatalf("%s: a later check was affected by an escalation: %+v", name, again)
		}
	}
}

func TestAHostedWatcherThatDisagreesWithNoPeersAtAllIsEscalated(t *testing.T) {
	rc := newRepeatContact(t, true)
	rc.ws.PeerWatchers = nil
	seen(t, rc.hosted, "EBob", 0, "Edifferent")
	if res := rc.again(t); res.OverallOutcome != "escalated" || !rc.sawEvent("kel_l3_escalation") {
		t.Fatalf("with nobody to ask: %+v events=%v", res, *rc.events)
	}
}

// Nobody is asked until the owner turns peer checks on, and the escalation
// is the same either way.
func TestWithPeerChecksOffNobodyIsAskedAndTheEscalationStands(t *testing.T) {
	rc := newRepeatContact(t, true)
	if err := rc.ws.Store.SetConfig(configPeerWatchEnabled, ""); err != nil {
		t.Fatal(err)
	}
	seen(t, rc.hosted, "EBob", 0, "Edifferent")
	res := rc.again(t)
	if res.OverallOutcome != "escalated" || *rc.asked != 0 {
		t.Fatalf("%+v asked=%d", res, *rc.asked)
	}
}

// Asking only where the answer changes something: nobody is asked when the
// hosted watcher agrees, has not seen the identity, or the verdict is already a block.
func TestContactsAreNotAskedWhenTheirAnswerChangesNothing(t *testing.T) {
	// The hosted watcher agrees.
	rc := newRepeatContact(t, true)
	d := rc.again(t).Digest
	seen(t, rc.hosted, "EBob", 0, d)
	if res := rc.again(t); res.OverallOutcome != "confirmed" || *rc.asked != 0 {
		t.Fatalf("agreeing hosted watcher: %+v asked=%d", res, *rc.asked)
	}

	// The hosted watcher has never seen him.
	rc = newRepeatContact(t, true)
	if res := rc.again(t); res.OverallOutcome != "confirmed" || *rc.asked != 0 {
		t.Fatalf("hosted watcher that has not met him: %+v asked=%d", res, *rc.asked)
	}

	// A repeat L1 mismatch blocks, with no question asked.
	rc = newRepeatContact(t, true)
	rc.kel = []map[string]interface{}{{"v": "KERI10JSON000256_", "t": "icp", "i": "EBob", "s": "0", "k": []string{"Dfork"}}}
	if res := rc.again(t); !res.Blocked || *rc.asked != 0 {
		t.Fatalf("fork: %+v asked=%d", res, *rc.asked)
	}
}

// First contact where the hosted watcher disagrees and cannot show why blocks
// nothing and asks nobody: it is shown, not acted on.
func TestAFirstContactDisagreementWithNoProofIsShownNotBlocked(t *testing.T) {
	rc := newRepeatContact(t, true)
	seen(t, rc.hosted, "EThird", 0, "Edifferent")
	third := []map[string]interface{}{{"v": "KERI10JSON000256_", "t": "icp", "i": "EThird", "s": "0"}}
	res, err := rc.ws.VerifyKel(context.Background(), VerifyKelInput{AID: "EThird", KEL: third, SourceType: SourceOOBI, SourceURL: rc.source})
	if err != nil {
		t.Fatal(err)
	}
	if res.Blocked || !res.OK || res.OverallOutcome != "escalated" || *rc.asked != 0 {
		t.Fatalf("%+v asked=%d", res, *rc.asked)
	}
}
