package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"
	"identity-agent-core/witness"

	keri "github.com/grapeid/keri-go"
)

// discardWorld is an Identity Agent that holds, from an agent's approval on,
// events an earlier version wrote without the key, which is now elsewhere. first
// is the place of the first of them.
func discardWorld(t *testing.T) (s *CoreServer, agentID, grant string, first int, e *elsewhere) {
	t.Helper()
	anAddonIssuingAIAgentGrants(t)
	s = appWorld(t)
	a, err := s.assetHandler.ProvisionAgentAsset("Researcher", []string{"agent.message.send"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, err = s.issueCapabilityGrant(a, coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := s.DataStore.GetIdentity()
	events, _ := s.DataStore.GetEvents(owner.AID)
	first = -1
	for _, ev := range events {
		if strings.Contains(ev.EventJSON, a.PairwiseAID) {
			first = ev.SequenceNumber
		}
	}
	if first < 1 {
		t.Fatal("the agent's approval is not in the key log")
	}
	recordDB(t, s).Exec(`UPDATE kel SET cesr_signature = '', signatures = '' WHERE aid = ? AND seq_num >= ?`, owner.AID, first)
	e = moveTheKeyElsewhere(t, s)
	s.router = s.buildRouter()
	return s, a.ID, grant, first, e
}

func discardIt(s *CoreServer) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, local("POST", "/api/key-log/unsigned-events/discard", ""))
	return rec
}

func keyLogLength(s *CoreServer) int {
	owner, _ := s.DataStore.GetIdentity()
	events, _ := s.DataStore.GetEvents(owner.AID)
	return len(events)
}

// What a refused discard leaves: the key log, the grant and the agent as they
// were, and nothing set aside.
func nothingWasDiscarded(t *testing.T, s *CoreServer, length int, grant, agentID string) {
	t.Helper()
	owner, _ := s.DataStore.GetIdentity()
	if keyLogLength(s) != length {
		t.Fatal("a refused discard changed the key log")
	}
	if aside, _ := s.DataStore.SupersededEvents(owner.AID); len(aside) != 0 {
		t.Fatal("a refused discard set events aside")
	}
	if c, _ := s.DataStore.GetCredential(grant); c == nil || c.Status == credentialStatusDiscarded {
		t.Fatalf("a refused discard undid the grant: %+v", c)
	}
	if a, _, _ := s.assetHandler.Store.GetAsset(agentID); a.ApprovalPending {
		t.Fatal("a refused discard sent the agent back to wait for its approval")
	}
}

// A witness that has receipted one of the events may hold it, and a different
// event at that place would read as duplicity: nothing is discarded, and the
// owner is pointed to signing them in place.
func TestEventsAWitnessHasReceiptedAreNotDiscarded(t *testing.T) {
	s, agentID, grant, first, _ := discardWorld(t)
	owner, _ := s.DataStore.GetIdentity()
	events, _ := s.DataStore.GetEvents(owner.AID)
	length := len(events)
	var said string
	for _, ev := range events {
		if ev.SequenceNumber == first {
			var body struct {
				D string `json:"d"`
			}
			if err := json.Unmarshal([]byte(ev.EventJSON), &body); err != nil || body.D == "" {
				t.Fatalf("event %d is unreadable: %v", first, err)
			}
			said = body.D
		}
	}
	wpub, wpriv, _ := ed25519.GenerateKey(rand.Reader)
	sig, _ := keri.MatterQB64(keri.CodeEd25519Sig, ed25519.Sign(wpriv, []byte(said)))
	if err := s.DataStore.SaveWitnessReceipt(store.WitnessReceiptRecord{EventSAID: said,
		WitnessAID: iacrypto.NonTransferableAIDQB64(wpub), CesrSignature: sig}); err != nil {
		t.Fatal(err)
	}
	rec := discardIt(s)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "/api/events/signature") {
		t.Fatalf("a receipted event: %d %s", rec.Code, rec.Body.String())
	}
	nothingWasDiscarded(t, s, length, grant, agentID)
}

// namesAWitness is an engine that says its identity names these witnesses.
type namesAWitness struct {
	*keriengine.Engine
	names []string
}

func (n namesAWitness) WitnessConfig(string) ([]string, int, error) { return n.names, 1, nil }

// Where the identity names a witness, it is asked: one that holds the first
// event or anything after it, or does not answer, stops the discard; one that
// holds only what is before it does not.
func TestEventsAWitnessMayHoldAreNotDiscarded(t *testing.T) {
	s, agentID, grant, first, _ := discardWorld(t)
	engine, ok := s.KeriDriver.(*keriengine.Engine)
	if !ok {
		t.Fatalf("the engine is a %T", s.KeriDriver)
	}
	wpub, wpriv, _ := ed25519.GenerateKey(rand.Reader)
	wkey := iacrypto.NonTransferableAIDQB64(wpub)
	s.KeriDriver = namesAWitness{Engine: engine, names: []string{wkey}}
	sq := s.DataStore.(*store.SQLiteStore)
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, s.KeriDriver, witness.BackendDesktop)
	s.DataStore.SaveContact(store.ContactRecord{AID: "EWitness0", OobiURL: "http://w0.test", Status: "active"})
	s.WitnessService.Store.SaveContactMeta(witness.ContactMeta{ContactAID: "EWitness0", WitnessKey: wkey})

	owner, _ := s.DataStore.GetIdentity()
	events, _ := s.DataStore.GetEvents(owner.AID)
	length := len(events)
	var held []store.EventRecord
	silent := false
	s.WitnessService.FetchTip = func(_ context.Context, url string) (witness.TipAnswer, error) {
		if silent {
			return witness.TipAnswer{}, errors.New("unreachable")
		}
		return witnessTip(url, held, wpriv, wkey), nil
	}

	for name, at := range map[string][]store.EventRecord{
		"it holds the first event": events[:first+1],
		"it holds the whole log":   events,
		"it holds a later event":   events[:first+2],
	} {
		held = at
		if rec := discardIt(s); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "/api/events/signature") {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
		nothingWasDiscarded(t, s, length, grant, agentID)
	}
	silent = true
	if rec := discardIt(s); rec.Code != http.StatusConflict {
		t.Fatalf("a witness that does not answer: %d %s", rec.Code, rec.Body.String())
	}
	nothingWasDiscarded(t, s, length, grant, agentID)

	silent, held = false, events[:first]
	if rec := discardIt(s); rec.Code != http.StatusOK {
		t.Fatalf("a witness holding only what is before: %d %s", rec.Code, rec.Body.String())
	}
	if keyLogLength(s) != first {
		t.Fatalf("the key log was rewound to %d events, want %d", keyLogLength(s), first)
	}
}

// The registry the discarded events anchored is unusable: a grant asked for
// afterwards does not go into it, and a registry is asked for afresh, anchored
// in the key log as it now is.
func TestARegistryWhoseInceptionWasDiscardedIsMadeAgain(t *testing.T) {
	s, _, _, _, _ := discardWorld(t)
	owner, _ := s.DataStore.GetIdentity()
	before, _ := s.DataStore.GetRegistryByIssuer(owner.AID)
	if before == nil || before.VcpRawB64 == "" {
		t.Fatalf("the fixture made no registry: %+v", before)
	}
	rec := discardIt(s)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), before.RegistrySAID) {
		t.Fatalf("discarding: %d %s", rec.Code, rec.Body.String())
	}
	if reg, _ := s.DataStore.GetRegistryByIssuer(owner.AID); reg == nil || reg.VcpRawB64 != "" {
		t.Fatalf("the registry the key log no longer anchors is still usable: %+v", reg)
	}
	// On next use a registry is made again, anchored in the key log as it now
	// is: the one the discarded events anchored is not issued into.
	owner.DerivationIndex -= 1000 // the key is back here, as where the device that held it is this one
	if err := s.DataStore.SaveIdentity(*owner); err != nil {
		t.Fatal(err)
	}
	made, err := s.ensureRegistry(owner.AID)
	if err != nil {
		t.Fatal(err)
	}
	if made == before.RegistrySAID {
		t.Fatal("a grant would go into the registry the key log no longer anchors")
	}
	if reg, _ := s.DataStore.GetRegistryByIssuer(owner.AID); reg == nil || reg.RegistrySAID != made || reg.VcpRawB64 == "" {
		t.Fatalf("the registry made again is not the one used: %+v", reg)
	}
}

// A registry the discarded events did not anchor stays in use.
func TestARegistryTheKeyLogStillAnchorsIsLeftUsable(t *testing.T) {
	s, _, _, _, _ := discardWorld(t)
	owner, _ := s.DataStore.GetIdentity()
	older := store.CredentialRegistry{RegistrySAID: "EAnOlderRegistryTheKeyLogStillAnchors000000000", IssuerAID: owner.AID,
		VcpRawB64: "e30=", CreatedAt: "2020-01-01T00:00:00Z"}
	if err := s.DataStore.SaveRegistry(older); err != nil {
		t.Fatal(err)
	}
	if rec := discardIt(s); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), older.RegistrySAID) {
		t.Fatalf("discarding: %d %s", rec.Code, rec.Body.String())
	}
	if reg, _ := s.DataStore.GetRegistry(older.RegistrySAID); reg == nil || reg.VcpRawB64 == "" {
		t.Fatal("a registry the key log still anchors was made unusable")
	}
}

// Only the owner discards.
func TestOnlyTheOwnerDiscardsUnsignedEvents(t *testing.T) {
	s, agentID, grant, _, _ := discardWorld(t)
	length := keyLogLength(s)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/key-log/unsigned-events/discard", nil) // from beyond this machine
	s.handleDiscardUnsignedEvents(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a caller that is not the owner: %d %s", rec.Code, rec.Body.String())
	}
	nothingWasDiscarded(t, s, length, grant, agentID)
}

// Where the key is held here, events are signed as they are written and
// nothing is ever rewound.
func TestNothingIsDiscardedWhereTheKeyIsHeldHere(t *testing.T) {
	anAddonIssuingAIAgentGrants(t)
	s := appWorld(t)
	a, _ := s.assetHandler.ProvisionAgentAsset("Researcher", []string{"agent.message.send"}, nil, nil, nil)
	grant, err := s.issueCapabilityGrant(a, coretypes.Authority{})
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := s.DataStore.GetIdentity()
	length := keyLogLength(s)
	recordDB(t, s).Exec(`UPDATE kel SET cesr_signature = '', signatures = '' WHERE aid = ? AND seq_num >= 1`, owner.AID)
	if _, err := s.discardUnsignedOwnEvents(); err == nil {
		t.Fatal("events were discarded where the key is held here")
	}
	nothingWasDiscarded(t, s, length, grant, a.ID)
}

// A failed reload of the engine is reported, with what was done and what to do.
func TestAnEngineThatCannotBeReloadedIsReported(t *testing.T) {
	s, _, _, _, _ := discardWorld(t)
	s.KeriDriver = unreloadable{s.KeriDriver.(*keriengine.Engine)}
	if _, err := s.discardUnsignedOwnEvents(); !errors.Is(err, errEngineNotReloaded) {
		t.Fatalf("an engine that could not be reloaded: %v", err)
	}
}

type unreloadable struct{ *keriengine.Engine }

func (unreloadable) ReloadIdentity(*drivers.DriverReloadIdentityRequest) (*drivers.DriverReloadIdentityResponse, error) {
	return nil, errors.New("no")
}

// An event marked as unsigned when this version took the log over is one
// ADR-061 says may be at witnesses: it is never discarded, even where no
// receipt is held and no witness is named, and the owner is pointed to signing
// it in place.
func TestAnEventMarkedUnsignedAtUpgradeIsNeverDiscarded(t *testing.T) {
	s, agentID, grant, first, _ := discardWorld(t)
	owner, _ := s.DataStore.GetIdentity()
	length := keyLogLength(s)
	if _, err := recordDB(t, s).Exec(`UPDATE kel SET unsigned_at_upgrade = 1 WHERE aid = ? AND seq_num = ?`, owner.AID, first); err != nil {
		t.Fatal(err)
	}
	rec := discardIt(s)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "/api/events/signature") {
		t.Fatalf("an event marked unsigned at the upgrade: %d %s", rec.Code, rec.Body.String())
	}
	nothingWasDiscarded(t, s, length, grant, agentID)
}

// A send of the key log to its witnesses that is in flight holds the discard
// back: the discard cannot ask the witnesses what they hold, and set the events
// aside, while a send that read them may still be on its way.
func TestASendInFlightBlocksTheDiscard(t *testing.T) {
	s, agentID, grant, _, _ := discardWorld(t)
	length := keyLogLength(s)
	s.witnessing.sendMu.Lock() // what sendLogToWitnesses holds while it sends
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- discardIt(s) }()
	select {
	case rec := <-done:
		s.witnessing.sendMu.Unlock()
		t.Fatalf("the discard went ahead of a send in flight: %d %s", rec.Code, rec.Body.String())
	case <-time.After(300 * time.Millisecond):
	}
	nothingWasDiscarded(t, s, length, grant, agentID)
	s.witnessing.sendMu.Unlock()
	if rec := <-done; rec.Code != http.StatusOK {
		t.Fatalf("the discard once the send was done: %d %s", rec.Code, rec.Body.String())
	}
}

// Every send of a key log to witnesses takes that lock, so the test above holds
// for them all: sendLogToWitnesses does not read or send while it is held.
func TestSendingTheLogWaitsForADiscardInProgress(t *testing.T) {
	s := appWorld(t)
	s.witnessing.sendMu.Lock()
	returned := make(chan struct{})
	go func() {
		s.sendLogToWitnesses(context.Background(), "E-none", nil, 0)
		close(returned)
	}()
	select {
	case <-returned:
		t.Fatal("a send went ahead while the key log was being discarded from")
	case <-time.After(200 * time.Millisecond):
	}
	s.witnessing.sendMu.Unlock()
	<-returned
}
