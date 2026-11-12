package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/drivers/signedlog"
	"identity-agent-core/store"
	"identity-agent-core/watcher"
)

// What a route verifies afterwards is verified against the log a watcher showed
// to be later, and its key state is the one that counts: a rotation may have
// retired the key the presented log ends on.
//
// Fails when watchedLog returns the presented records instead of the adopted
// ones: the key state read off what it returns is then the retired one.
func TestTheRoutesVerifyAgainstTheLaterKeyStateAWatcherShowed(t *testing.T) {
	base := signedlog.Incept(t, signedlog.NewKeys(t, 3)).Interact("one")
	later := base.Fork().Rotate().Interact("after")
	s := witnessWithSeed(t, 7)
	aStandingWatcherHolding(t, s, base.AID, withParsedFields(later.Records()))

	got, res := s.watchedLog(context.Background(), base.AID, withParsedFields(base.Records()), watcher.SourceOOBI, "https://x.example/oobi", nil)
	if res == nil || res.Stopped() {
		t.Fatalf("the check: %+v", res)
	}
	if len(got) != later.Len() {
		t.Fatalf("the log to go on with has %d events, want the watcher's %d", len(got), later.Len())
	}
	msgs, err := drivers.SignedMessagesFromRecords(got)
	if err != nil {
		t.Fatal(err)
	}
	v, err := keri.ValidateSignedKEL(msgs)
	if err != nil || len(v.Keys) != 1 || v.Keys[0] != later.Key() || v.Keys[0] == base.Key() {
		t.Fatalf("the key state to verify against is %v (%v), want the later key %s and not the earlier one %s", v.Keys, err, later.Key(), base.Key())
	}
}

// A check that cannot be completed refuses; it does not let every route go on as
// if it had found nothing. A store fault is made here by dropping what the
// watcher records a sighting in, which an unproven log (parsed records only)
// reaches first.
//
// Fails when runWatcherOnKel goes back to returning nil on an error from VerifyKel.
func TestACheckThatCannotBeCompletedRefusesTheLog(t *testing.T) {
	s := watcherAgent(t, "EOther", 1, "Ed")
	if _, err := s.DataStore.(*store.SQLiteStore).DB().Exec(`DROP TABLE kel_first_seen`); err != nil {
		t.Fatal(err)
	}
	kel := []map[string]interface{}{{"v": "KERI10JSON000160_", "t": "icp", "i": "ENamer", "s": "0", "d": "Eevent-0"}}
	res := s.runWatcherOnKel(context.Background(), "ENamer", kel, watcher.SourceOOBI, "https://x.example/oobi", nil)
	if res == nil || !res.Stopped() || res.OK {
		t.Fatalf("a failed check let the log through: %+v", res)
	}
	if c := res.Check(); c.Verdict != watcher.VerdictUnchecked {
		t.Fatalf("it is not shown as a duplicity finding about the identity: %s", c.Verdict)
	}
	// And a route stops on it.
	honest, _ := twoSignedHistories(t)
	s.KeriDriver = anEngineThatVerifies(honest.Key(), honest.Len())
	peer := aPeerServing(t, honest.AID, honest.Key(), withParsedFields(honest.Records()))
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	rec := aRecordedPost(s.handleResolveOobiContact, "/api/oobi/resolve", map[string]interface{}{"oobi_url": peer.URL + "/oobi/" + honest.AID, "alias": "x"})
	if rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "could not be completed") {
		t.Fatalf("resolve went ahead on a check that failed: %d %s", rec.Code, rec.Body.String())
	}
}
