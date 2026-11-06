package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"identity-agent-core/keriengine"
	"identity-agent-core/store"
	"identity-agent-core/witness"

	keri "github.com/grapeid/keri-go"
)

// issuerWitnessedBy is an agent that founds its identity naming bob as its one
// witness, with bob its enrolled witness contact reachable at bobURL.
type pushWorld struct {
	t    *testing.T
	s    *CoreServer
	bob  *peerAgent
	aid  string
	eng  *keriengine.Engine
	cont store.ContactRecord
}

func newPushWorld(t *testing.T) *pushWorld {
	t.Helper()
	bob := startPeer(t, "bob")
	s := agentWithDerivedIdentity(t)
	aid, eng := foundOrganisation(t, s, []string{bob.witnessKey}, 1)
	s.engineKeepsCredentialLogs() // as startup does
	svc := witness.NewService(witness.NewSQLiteStore(s.DataStore.(*store.SQLiteStore).DB()), s.DataStore, nil, witness.BackendDesktop)
	svc.OurEntityType = func() witness.EntityType { return witness.EntityIndividual }
	s.WitnessService = svc
	s.telPushRetryGap = func(int) time.Duration { return 0 } // these tests retry at once; the gaps have their own
	bob.willWitnessFor(t, aid)
	w := &pushWorld{t: t, s: s, bob: bob, aid: aid, eng: eng}
	w.contactAt(bob.base)
	return w
}

// contactAt makes bob reachable at base, or not at all if base is dead.
func (w *pushWorld) contactAt(base string) {
	w.t.Helper()
	c := store.ContactRecord{AID: "EBOBCONTACT", Status: "accepted", ContactCategory: "general", IsWitness: true, OobiURL: base}
	// The witnessing worker, kicked by an issuance, reads the same database.
	var err error
	for i := 0; i < 50; i++ {
		if err = w.s.DataStore.SaveContact(c); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		w.t.Fatal(err)
	}
	if err := w.s.WitnessService.Store.SaveContactMeta(witness.ContactMeta{
		ContactAID: c.AID, BackendType: witness.BackendDesktop, EntityType: "individual",
		WitnessKey: w.bob.witnessKey, WitnessStatus: witness.StatusOnline,
	}); err != nil {
		w.t.Fatal(err)
	}
}

// bobHoldsTheKeyLog gives bob the identity's key log, as the witnessing worker
// does before the registry events can be placed. That worker runs in the
// background from the issuance on and may deliver the same event at the same
// moment, so a refusal here is not a failure: what counts is that bob ends up
// holding the whole log, whoever delivered it.
func (w *pushWorld) bobHoldsTheKeyLog() {
	w.t.Helper()
	events := w.s.signedEventsOf(w.aid)
	var last error
	for i := 0; i < 100; i++ {
		held, _ := w.bob.svc.GetKelReplica(w.aid)
		if len(held) >= len(events) {
			return
		}
		ev := events[len(held)]
		raw, _ := b64Decode(ev.RawBytesB64)
		last = w.bob.takes(w.t, w.aid, raw, ev.CesrSignature)
		if last != nil {
			time.Sleep(20 * time.Millisecond)
		}
	}
	w.t.Fatalf("bob never came to hold the identity's key log: %v", last)
}

func (w *pushWorld) issue() {
	w.t.Helper()
	reg, err := w.eng.InceptRegistry(w.aid)
	if err != nil {
		w.t.Fatal(err)
	}
	schema, _ := keri.Blake3SAID([]byte("a test schema"))
	if _, err := w.eng.IssueCredentialInRegistry(w.aid, map[string]interface{}{"role": "engineer"},
		schema, "EHolder000000000000000000000000000000000000", nil, reg.RegistrySaid); err != nil {
		w.t.Fatalf("the issuance failed: %v", err)
	}
}

func (w *pushWorld) pending() []store.TELPush {
	w.t.Helper()
	p, err := w.s.DataStore.PendingTELPushes(100)
	if err != nil {
		w.t.Fatal(err)
	}
	return p
}

func (w *pushWorld) bobServes() (int, int) {
	w.t.Helper()
	ans, err := w.bob.svc.ServeTEL(w.aid, -1)
	if err != nil {
		return 0, 0
	}
	return len(ans.Events), ans.AnchoredSN
}

// Issuing into a registry sends the events to the identity's witnesses, so a
// verifier outside can find them. A witness that cannot be reached does not
// fail the issuance, the events wait, and a later pass delivers them.
func TestAnIssuanceIsSentToTheIdentitysWitnessesAndNeverFailedByThem(t *testing.T) {
	w := newPushWorld(t)

	// The witness is not reachable: the issuance goes through and its events wait.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	w.contactAt(deadURL)
	w.issue() // fails the test if the issuance fails
	if p := w.pending(); len(p) != 2 || p[0].Kind != "vcp" || p[1].Kind != "iss" {
		t.Fatalf("the registry's inception and the issuance should wait to be sent, in order: %+v", p)
	}
	w.s.pushRegistryEvents(context.Background())
	p := w.pending()
	// (The witnessing worker, kicked by the issuance, may have tried too.)
	if len(p) != 2 || p[0].Attempts < 1 || p[0].LastError == "" {
		t.Fatalf("a failed attempt is not recorded: %+v", p)
	}

	// Reachable, but it does not yet hold the key-log event that seals them:
	// refused, and still waiting.
	w.contactAt(w.bob.base)
	w.s.pushRegistryEvents(context.Background())
	if n, _ := w.bobServes(); n != 0 || len(w.pending()) != 2 {
		t.Fatalf("a witness that cannot see the seal kept an event (%d), or the outbox lost them (%d)", n, len(w.pending()))
	}

	// Once it holds the key log the next pass delivers, and the outbox empties.
	w.bobHoldsTheKeyLog()
	w.s.pushRegistryEvents(context.Background())
	w.eventually(func() bool { n, anchored := w.bobServes(); return n == 2 && anchored == 2 && len(w.pending()) == 0 },
		"the witness should serve the inception and the issuance, anchored through 2, with nothing left waiting")
}

// eventually waits for what the background witnessing worker and the pass the
// test runs itself have between them done.
func (w *pushWorld) eventually(ok func() bool, what string) {
	w.t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		w.s.pushRegistryEvents(context.Background())
		time.Sleep(50 * time.Millisecond)
	}
	n, anchored := w.bobServes()
	w.t.Fatalf("%s: it serves %d events through %d, and %d wait", what, n, anchored, len(w.pending()))
}

func TestARevocationIsSentToTheWitnessesToo(t *testing.T) {
	w := newPushWorld(t)
	reg, _ := w.eng.InceptRegistry(w.aid)
	schema, _ := keri.Blake3SAID([]byte("a test schema"))
	iss, err := w.eng.IssueCredentialInRegistry(w.aid, map[string]interface{}{"role": "engineer"},
		schema, "EHolder000000000000000000000000000000000000", nil, reg.RegistrySaid)
	if err != nil {
		t.Fatal(err)
	}
	w.bobHoldsTheKeyLog()
	w.s.pushRegistryEvents(context.Background())
	if _, err := w.eng.RevokeCredential(w.aid, iss.AcdcSaid, reg.RegistrySaid, iss.IssSaid); err != nil {
		t.Fatal(err)
	}
	w.bobHoldsTheKeyLog()
	w.eventually(func() bool { n, anchored := w.bobServes(); return n == 3 && anchored == 3 && len(w.pending()) == 0 },
		"the witness should serve the revocation too")
}

func b64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
