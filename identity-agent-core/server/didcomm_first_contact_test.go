package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/didcomm"
	"identity-agent-core/store"
)

// The first message between two agents that have never exchanged one.
//
// Inbound delivery refuses an unknown sender, which is right. But it made first
// contact impossible in one direction: the sender can read the recipient's
// public DID document, and the recipient has no way to read the sender's. Found
// on hardware — an organisation could fetch a customer's keys and its message
// still came back 403, and registering the peer by hand made the identical
// message land immediately.
//
// The distinction that resolves it is between "unknown" and "stranger". An
// accepted contact is somebody the owner already looked at and approved.

func TestAnAcceptedContactCanReachUsFirst(t *testing.T) {
	s := serverWithIdentity(t, "EOURS")

	// A real agent, publishing a real DID document the way the public route
	// does — so this proves the whole resolution, not just that it was
	// attempted.
	keys, err := didcomm.GenerateKeySet("EKNOWN")
	if err != nil {
		t.Fatal(err)
	}
	did, err := keys.DID()
	if err != nil {
		t.Fatal(err)
	}
	theirAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/didcomm/did" || r.URL.Query().Get("aid") != "EKNOWN" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(did)
	}))
	defer theirAgent.Close()

	if err := s.DataStore.SaveContact(store.ContactRecord{
		AID: "EKNOWN", Alias: "somebody we accepted",
		OobiURL: theirAgent.URL + "/public/oobi/EKNOWN?role=controller",
		Status:  "accepted",
	}); err != nil {
		t.Fatal(err)
	}

	resolved, err := s.resolveKnownContactAsPeer("EKNOWN")
	if err != nil {
		t.Fatalf("an accepted contact could not be resolved: %v", err)
	}
	if !resolved {
		t.Fatal("an accepted contact was not resolved, so their first message would be refused")
	}

	// And they are now a peer, which is what makes the next envelope land.
	didcommMu.Lock()
	peer, ok := s.loadPeers()["EKNOWN"]
	didcommMu.Unlock()
	if !ok {
		t.Fatal("resolution reported success and registered nothing")
	}
	if peer.DID.AID != "EKNOWN" {
		t.Errorf("registered keys for %q", peer.DID.AID)
	}
	if peer.Endpoint != theirAgent.URL+"/didcomm" {
		t.Errorf("endpoint is %q", peer.Endpoint)
	}
}

// The keys must be the ones that identifier published. An agent answering with
// somebody else's keys would receive messages meant for them.
func TestResolutionRefusesKeysForADifferentIdentifier(t *testing.T) {
	s := serverWithIdentity(t, "EOURS")

	keys, _ := didcomm.GenerateKeySet("ESOMEBODY-ELSE")
	did, _ := keys.DID()
	theirAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(did)
	}))
	defer theirAgent.Close()

	s.DataStore.SaveContact(store.ContactRecord{
		AID: "EKNOWN", OobiURL: theirAgent.URL + "/public/oobi/EKNOWN", Status: "accepted",
	})

	if resolved, _ := s.resolveKnownContactAsPeer("EKNOWN"); resolved {
		t.Fatal("keys published for one identifier were registered under another")
	}
}

// A stranger is still a stranger. Nothing is fetched on the say-so of somebody
// the owner has never approved, or an anonymous POST naming any identifier
// becomes a way to make this agent issue outbound requests.
func TestAStrangerIsNotResolved(t *testing.T) {
	s := serverWithIdentity(t, "EOURS")

	resolved, err := s.resolveKnownContactAsPeer("ENEVER-HEARD-OF-THEM")
	if resolved {
		t.Fatal("an unknown identifier was resolved")
	}
	if err != nil {
		t.Errorf("a stranger should be an ordinary no, not an error: %v", err)
	}
}

// A pending contact is one the owner has NOT agreed to hear from. Treating a
// row as consent would make an unanswered introduction into an open door.
func TestAPendingContactIsNotResolved(t *testing.T) {
	s := serverWithIdentity(t, "EOURS")
	for _, status := range []string{"pending_inbound", "pending_outbound", "rejected", "blocked"} {
		aid := "E" + status
		if err := s.DataStore.SaveContact(store.ContactRecord{
			AID: aid, OobiURL: "http://127.0.0.1:9/public/oobi/" + aid, Status: status,
		}); err != nil {
			t.Fatal(err)
		}
		if resolved, _ := s.resolveKnownContactAsPeer(aid); resolved {
			t.Errorf("a %q contact was resolved as though the owner had accepted them", status)
		}
	}
}

// The address comes from the contact record, never from the caller, so a sender
// cannot point this at somewhere of its choosing. These are the shapes that
// record actually holds.
func TestAnAgentAddressIsRecoveredFromItsOOBI(t *testing.T) {
	for _, tc := range []struct{ oobi, want string }{
		{"https://agent.example/public/oobi/EABC?role=controller", "https://agent.example"},
		{"https://agent.example/public/oobi/EABC", "https://agent.example"},
		{"https://agent.example/oobi/EABC", "https://agent.example"},
		{"http://127.0.0.1:5102/public/oobi/EABC", "http://127.0.0.1:5102"},
		{"https://agent.example/EABC/oobi", "https://agent.example"},
	} {
		got, err := agentBaseFromOOBI(tc.oobi)
		if err != nil {
			t.Errorf("%s: %v", tc.oobi, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s\n got %q\nwant %q", tc.oobi, got, tc.want)
		}
	}
}

// A guess at a hostname is a request sent somewhere nobody chose.
func TestAnUnrecognisableOOBIIsRefusedRatherThanGuessedAt(t *testing.T) {
	for _, bad := range []string{
		"", "not a url", "agent.example/public/oobi/EABC",
		"ftp://agent.example/public/oobi/EABC", "https://agent.example",
	} {
		if got, err := agentBaseFromOOBI(bad); err == nil {
			t.Errorf("%q was turned into the address %q", bad, got)
		}
	}
}
