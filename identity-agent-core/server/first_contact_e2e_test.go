package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/didcomm"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

// A driver that accepts a key history as sound. The validation itself is
// exercised against the real KERI library elsewhere; what this covers is what
// this agent does with the answer.
func acceptingKELDriver(t *testing.T) *drivers.KeriDriver {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/validate-kel" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"kel_verified": true, "events_validated": 1, "current_public_key": "Dkey",
		})
	}))
	t.Cleanup(srv.Close)
	return drivers.NewKeriDriverAt(srv.URL)
}

// A stranger's inception event, committing to the keys it will actually use.
func inceptionCommittingTo(t *testing.T, aid string, ks *didcomm.KeySet) []map[string]interface{} {
	t.Helper()
	kem, err := ks.KemPub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	dsa, err := ks.DsaPub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := iacrypto.KeySetAnchor(ks.XPub[:], kem, ks.EdPub, dsa)
	if err != nil {
		t.Fatal(err)
	}
	return []map[string]interface{}{{
		"v": "KERI10JSON", "t": "icp", "s": "0", "i": aid, "d": aid,
		"a": []interface{}{anchor},
	}}
}

// The whole point, end to end through the public endpoint: two agents that have
// never met, and nothing fetched by either.
func TestAStrangerCarryingProofGetsInFrontOfTheOwner(t *testing.T) {
	const strangerAID = "EStrangerWithProof"
	receiver := witnessWithSeed(t, 1)
	receiver.KeriDriver = acceptingKELDriver(t)

	// The receiver's own identity, which the stranger addresses.
	const ourAID = "EReceiver"
	ourKeys, err := receiver.keySetFor(ourAID)
	if err != nil {
		t.Fatal(err)
	}
	ourDID, err := ourKeys.DID()
	if err != nil {
		t.Fatal(err)
	}

	// The stranger, and the history that commits to its keys.
	strangerKeys, err := didcomm.GenerateKeySet(strangerAID)
	if err != nil {
		t.Fatal(err)
	}
	kel := inceptionCommittingTo(t, strangerAID, strangerKeys)

	body, _ := json.Marshal(map[string]string{"alias": "A Stranger"})
	jwm := &didcomm.JWM{
		ID: "msg-first", Type: didcomm.TypeContactRequest,
		From: "did:keri:" + strangerAID, To: []string{"did:keri:" + ourAID},
		Body: body,
	}
	env, err := didcomm.PackAuthcrypt(strangerKeys, ourDID, jwm)
	if err != nil {
		t.Fatal(err)
	}
	env.SenderKEL = kel

	raw, _ := json.Marshal(env)
	w := httptest.NewRecorder()
	receiver.handleDIDCommInbound(w, httptest.NewRequest(http.MethodPost, "/didcomm", bytes.NewReader(raw)))

	if w.Code != http.StatusAccepted {
		t.Fatalf("a stranger carrying proof was refused: %d %s", w.Code, w.Body.String())
	}

	rec, _ := receiver.DataStore.GetContact(strangerAID)
	if rec == nil {
		t.Fatal("nothing was put in front of the owner")
	}
	if rec.Status == "accepted" {
		t.Fatalf("proving a name was treated as being agreed to: %q", rec.Status)
	}
	if _, known := receiver.loadPeers()[strangerAID]; known {
		t.Fatal("a stranger was registered as a peer before the owner agreed")
	}
}

// Keys that the presented history does not commit to must not open anything.
// This is the substitution the whole scheme exists to refuse.
func TestAStrangerCannotPresentSomebodyElsesHistory(t *testing.T) {
	const strangerAID = "EImpostor"
	receiver := witnessWithSeed(t, 1)
	receiver.KeriDriver = acceptingKELDriver(t)

	ourKeys, _ := receiver.keySetFor("EReceiver")
	ourDID, _ := ourKeys.DID()

	// Sends with one keyset, presents a history committing to another.
	actual, _ := didcomm.GenerateKeySet(strangerAID)
	other, _ := didcomm.GenerateKeySet(strangerAID)

	body, _ := json.Marshal(map[string]string{"alias": "Not Me"})
	jwm := &didcomm.JWM{
		ID: "msg-forged", Type: didcomm.TypeContactRequest,
		From: "did:keri:" + strangerAID, To: []string{"did:keri:EReceiver"},
		Body: body,
	}
	env, err := didcomm.PackAuthcrypt(actual, ourDID, jwm)
	if err != nil {
		t.Fatal(err)
	}
	env.SenderKEL = inceptionCommittingTo(t, strangerAID, other)

	raw, _ := json.Marshal(env)
	w := httptest.NewRecorder()
	receiver.handleDIDCommInbound(w, httptest.NewRequest(http.MethodPost, "/didcomm", bytes.NewReader(raw)))

	if w.Code == http.StatusAccepted {
		t.Fatal("an envelope opened with keys the presented history does not commit to")
	}
	if rec, _ := receiver.DataStore.GetContact(strangerAID); rec != nil {
		t.Fatal("a request was recorded for a sender that never proved who it was")
	}
}

// However well identified, a stranger may only ask to connect.
func TestAStrangerCannotDeliverACredential(t *testing.T) {
	const strangerAID = "EWellIdentifiedStranger"
	receiver := witnessWithSeed(t, 1)
	receiver.KeriDriver = acceptingKELDriver(t)

	ourKeys, _ := receiver.keySetFor("EReceiver")
	ourDID, _ := ourKeys.DID()
	strangerKeys, _ := didcomm.GenerateKeySet(strangerAID)

	body, _ := json.Marshal(map[string]string{"said": "ECred", "acdc_json": "{}"})
	jwm := &didcomm.JWM{
		ID: "msg-sneak", Type: didcomm.TypeCredentialIssuance,
		From: "did:keri:" + strangerAID, To: []string{"did:keri:EReceiver"},
		Body: body,
	}
	env, err := didcomm.PackAuthcrypt(strangerKeys, ourDID, jwm)
	if err != nil {
		t.Fatal(err)
	}
	env.SenderKEL = inceptionCommittingTo(t, strangerAID, strangerKeys)

	raw, _ := json.Marshal(env)
	w := httptest.NewRecorder()
	receiver.handleDIDCommInbound(w, httptest.NewRequest(http.MethodPost, "/didcomm", bytes.NewReader(raw)))

	if w.Code == http.StatusAccepted {
		t.Fatal("a stranger delivered a credential by proving who they were")
	}
	if creds, _ := receiver.DataStore.GetCredentials(); len(creds) != 0 {
		t.Fatal("a credential from a stranger was stored")
	}
}

// Approving a request uses the history that was checked when it arrived, rather
// than asking again — the owner agrees to what they were shown.
func TestApprovingAStrangerEstablishesThemFromWhatWasVerified(t *testing.T) {
	const strangerAID = "EApprovedStranger"
	s := witnessWithSeed(t, 1)
	s.KeriDriver = acceptingKELDriver(t)

	strangerKeys, _ := didcomm.GenerateKeySet(strangerAID)
	kel := inceptionCommittingTo(t, strangerAID, strangerKeys)
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: strangerAID, KEL: kel, KelVerified: true, EventsValidated: 1,
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.registerPeerFromVerifiedHistory(strangerAID,
		"http://stranger.example/public/oobi/"+strangerAID); err != nil {
		t.Fatalf("approving did not establish the peer: %v", err)
	}

	peer, known := s.loadPeers()[strangerAID]
	if !known {
		t.Fatal("an approved stranger was not established as a peer")
	}
	// The keys recorded must be the ones the history committed to.
	want, _ := strangerKeys.DID()
	if peer.DID.X25519 != want.X25519 || peer.DID.Ed != want.Ed {
		t.Fatal("the peer was recorded with keys other than the ones that were verified")
	}
	if peer.Endpoint != "http://stranger.example/didcomm" {
		t.Fatalf("peer endpoint is %q", peer.Endpoint)
	}
}

// Knowing who somebody is does not tell you where they are.
func TestAnApprovedStrangerWithNoAddressIsNotEstablished(t *testing.T) {
	const strangerAID = "ENoAddress"
	s := witnessWithSeed(t, 1)
	strangerKeys, _ := didcomm.GenerateKeySet(strangerAID)
	_ = s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: strangerAID, KEL: inceptionCommittingTo(t, strangerAID, strangerKeys),
		KelVerified: true, EventsValidated: 1,
	})
	if err := s.registerPeerFromVerifiedHistory(strangerAID, ""); err == nil {
		t.Fatal("a peer was recorded with no address to reach it at")
	}
	if _, known := s.loadPeers()[strangerAID]; known {
		t.Fatal("a peer was recorded despite having no address")
	}
}
