package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/didcomm"
	"identity-agent-core/drivers"
	"identity-agent-core/drivers/driverfake"
	"identity-agent-core/store"
)

// A peer that serves one OOBI answer carrying the given log.
func aPeerServing(t *testing.T, aid, key string, kel []map[string]interface{}) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": aid, "public_key": key, "alias": "peer", "kel": kel,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func anEngineThatVerifies(key string, events int) *driverfake.Engine {
	ok := func() (*drivers.DriverValidateKELResponse, error) {
		return &drivers.DriverValidateKELResponse{KelVerified: true, CurrentPublicKey: key, EventsValidated: events}, nil
	}
	return &driverfake.Engine{
		ValidateKELFunc:      func(string, []map[string]interface{}) (*drivers.DriverValidateKELResponse, error) { return ok() },
		ValidateKELBytesFunc: func(drivers.ValidateKELInput) (*drivers.DriverValidateKELResponse, error) { return ok() },
	}
}

func heldKeyIsStill(t *testing.T, s *CoreServer, aid, key string, events int) {
	t.Helper()
	held, _ := s.DataStore.GetContactKEL(aid)
	if held == nil || held.CurrentPublicKey != key || len(held.KEL) != events {
		t.Fatalf("the held log changed: %+v", held)
	}
}

// EnsureKeriContact is handed the earlier half of a log this machine already
// holds in full. It must refuse and record no contact.
//
// Fails when the errors.Is(serr, store.ErrLogDoesNotExtend) return in
// ensureKeriContactIs (keri_contact.go) is removed: the contact is then recorded
// with the earlier log's key.
func TestEnsureKeriContactRefusesAnEarlierLogAndRecordsNoContact(t *testing.T) {
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	keys, real, _ := theRealLogAndAForkOfIt(t)
	earlier := real.Cut(2)
	s := witnessWithSeed(t, 4)
	s.KeriDriver = anEngineThatVerifies(earlier.Key(), earlier.Len())
	if err := holdVerified(t, s, real); err != nil {
		t.Fatal(err)
	}
	srv := aPeerServing(t, real.AID, earlier.Key(), earlier.Records())

	c, created, err := s.EnsureKeriContact(srv.URL + "/oobi/" + real.AID)
	if err == nil || !strings.Contains(err.Error(), "does not carry on") {
		t.Fatalf("an earlier log was taken: %+v created=%v err=%v", c, created, err)
	}
	if rec, _ := s.DataStore.GetContact(real.AID); rec != nil {
		t.Fatalf("a contact was recorded from a refused log: %+v", rec)
	}
	heldKeyIsStill(t, s, real.AID, keys.Pub(2), real.Len())
}

// The add-contact handler is offered a fork of the held log, which the store
// refuses. The caller is told so, and no contact appears.
//
// Fails when the errors.Is(err, store.ErrLogDoesNotExtend) block in
// handleAddContact (server.go) is removed: the handler answers 200 and adds the
// contact with the fork's key.
func TestAddContactRefusesAForkedLogAndAddsNoContact(t *testing.T) {
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	keys, real, fork := theRealLogAndAForkOfIt(t)
	s := witnessWithSeed(t, 5)
	s.KeriDriver = anEngineThatVerifies(fork.Key(), fork.Len())
	if err := holdVerified(t, s, real); err != nil {
		t.Fatal(err)
	}
	srv := aPeerServing(t, real.AID, fork.Key(), fork.Records())

	body, _ := json.Marshal(map[string]interface{}{"oobi_url": srv.URL + "/oobi/" + real.AID, "alias": "x"})
	rec := httptest.NewRecorder()
	s.handleAddContact(rec, httptest.NewRequest(http.MethodPost, "/api/contacts", bytes.NewReader(body)))

	if rec.Code != http.StatusConflict {
		t.Fatalf("adding a contact from a forked log: %d %s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(fork.Key())) {
		t.Fatalf("the refused log's key was reported: %s", rec.Body.String())
	}
	if c, _ := s.DataStore.GetContact(real.AID); c != nil {
		t.Fatalf("a contact was added from a refused log: %+v", c)
	}
	heldKeyIsStill(t, s, real.AID, keys.Pub(2), real.Len())
}

// A stranger proves who they are with the first event of a history this machine
// already holds further along. The introduction is refused, and no request
// reaches the owner.
//
// Fails when the errors.Is(err, store.ErrLogDoesNotExtend) block in
// tryFirstContact (first_contact.go) is removed: the request is recorded and
// answered 202 on the strength of a log that was not kept.
func TestFirstContactRefusesAnEarlierLogAndPutsNothingInFrontOfTheOwner(t *testing.T) {
	const strangerAID = "EStrangerWithAnEarlierLog"
	receiver := witnessWithSeed(t, 6)
	receiver.KeriDriver = acceptingKELDriver(t)

	const ourAID = "EReceiver"
	ourKeys, err := receiver.keySetFor(ourAID)
	if err != nil {
		t.Fatal(err)
	}
	ourDID, err := ourKeys.DID()
	if err != nil {
		t.Fatal(err)
	}
	strangerKeys, err := didcomm.GenerateKeySet(strangerAID)
	if err != nil {
		t.Fatal(err)
	}
	inception := inceptionCommittingTo(t, strangerAID, strangerKeys)
	later := withTheBytesItWasVerifiedBy(t, map[string]interface{}{
		"v": "KERI10JSON", "t": "ixn", "s": "1", "i": strangerAID, "d": "ELaterEvent",
	})
	// This machine already trusts the history one event further along.
	if err := receiver.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: strangerAID, KEL: append(append([]map[string]interface{}{}, inception...), later...),
		KelVerified: true, CurrentPublicKey: fixtureKey, EventsValidated: 2,
	}); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]string{"alias": "A Stranger"})
	jwm := &didcomm.JWM{
		ID: "msg-first", Type: didcomm.TypeContactRequest,
		From: "did:keri:" + strangerAID, To: []string{"did:keri:" + ourAID}, Body: body,
	}
	env, err := didcomm.PackAuthcrypt(strangerKeys, ourDID, jwm)
	if err != nil {
		t.Fatal(err)
	}
	env.SenderKEL = inception // the earlier half only
	raw, _ := json.Marshal(env)
	w := httptest.NewRecorder()
	receiver.handleDIDCommInbound(w, httptest.NewRequest(http.MethodPost, "/didcomm", bytes.NewReader(raw)))

	if w.Code != http.StatusConflict {
		t.Fatalf("an earlier log was taken: %d %s", w.Code, w.Body.String())
	}
	if rec, _ := receiver.DataStore.GetContact(strangerAID); rec != nil {
		t.Fatalf("a request reached the owner from a refused log: %+v", rec)
	}
	if held, _ := receiver.DataStore.GetContactKEL(strangerAID); held == nil || len(held.KEL) != 2 {
		t.Fatalf("the held log changed: %+v", held)
	}
}

// The attack through the OOBI resolve route, which saves whatever verdict the
// engine gives. The peer serves the real log with the engine finding a bad
// signature in it (so it is saved as unverified), then a fork the engine passes.
// Neither may replace the verified log held, and the owner's key stays K3.
//
// Fails when the `!offered.KelVerified` refusal in refuseAnEarlierLog
// (store/store.go) is removed: the first request is answered 200 and replaces
// the verified log, and the second then installs the fork's retired key.
func TestOobiResolveCannotReplaceAVerifiedLogWithAnUnverifiedCopyThenAFork(t *testing.T) {
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	keys, real, fork := theRealLogAndAForkOfIt(t)
	s := witnessWithSeed(t, 7)
	if err := holdVerified(t, s, real); err != nil {
		t.Fatal(err)
	}
	resolve := func(srv *httptest.Server) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"oobi_url": srv.URL + "/oobi/" + real.AID})
		rec := httptest.NewRecorder()
		s.handleResolveOobiContact(rec, httptest.NewRequest(http.MethodPost, "/api/contacts/resolve", bytes.NewReader(body)))
		return rec
	}

	// Step 2: the real events, the engine says a signature is bad.
	s.KeriDriver = &driverfake.Engine{
		ValidateKELBytesFunc: func(drivers.ValidateKELInput) (*drivers.DriverValidateKELResponse, error) {
			return &drivers.DriverValidateKELResponse{KelVerified: false, CurrentPublicKey: real.Key(), EventsValidated: real.Len(),
				ValidationErrors: []string{"event signature does not verify"}}, nil
		},
	}
	if rec := resolve(aPeerServing(t, real.AID, real.Key(), real.Records())); rec.Code != http.StatusConflict {
		t.Fatalf("an unverified copy of the held log was taken: %d %s", rec.Code, rec.Body.String())
	}
	if held, _ := s.DataStore.GetContactKEL(real.AID); held == nil || !held.KelVerified {
		t.Fatalf("the verified log was replaced by an unverified one: %+v", held)
	}

	// Step 3: a fork from the retired K2 that the engine passes.
	s.KeriDriver = anEngineThatVerifies(fork.Key(), fork.Len())
	if rec := resolve(aPeerServing(t, real.AID, fork.Key(), fork.Records())); rec.Code != http.StatusConflict {
		t.Fatalf("a fork was taken after the unverified copy: %d %s", rec.Code, rec.Body.String())
	}
	heldKeyIsStill(t, s, real.AID, keys.Pub(2), real.Len())
}
