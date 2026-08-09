package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
)

// A driver that hands back an inception event carrying whatever anchors it was
// given, which is what keripy does. Enough to exercise what this agent sends
// and what it does with the result, without a KERI runtime.
func fakeInceptionDriver(t *testing.T, aid string, seen *map[string]interface{}) *drivers.KeriDriver {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/inception" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if seen != nil {
			*seen = req
		}
		event := map[string]interface{}{
			"v": "KERI10JSON", "t": "icp", "s": "0", "i": aid,
			"k": []interface{}{req["public_key"]},
		}
		if a, ok := req["anchors"]; ok {
			event["a"] = a
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"aid":             aid,
			"inception_event": event,
			"public_key":      req["public_key"],
			"next_key_digest": "Enext",
			"raw_bytes_b64":   "",
		})
	}))
	t.Cleanup(srv.Close)
	return drivers.NewKeriDriverAt(srv.URL)
}

// The loop that had never closed: an identity founded here commits to its own
// messaging keys, and the keys it later publishes are those same keys.
//
// Before this, every identifier answered "not anchored", so the strong half of
// the peer-key check was unreachable and every agent fell back to being taken
// at its word.
func TestAFoundedIdentityCommitsToTheKeysItPublishes(t *testing.T) {
	const aid = "EFoundedHere"
	s := witnessWithSeed(t, 1)
	var sent map[string]interface{}
	s.KeriDriver = fakeInceptionDriver(t, aid, &sent)

	w := inceptionRequest(t, s, map[string]any{
		"public_key": "Dpub", "next_public_key": "Dnext",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("inception failed: %d %s", w.Code, w.Body.String())
	}

	// What went into the event.
	anchors, _ := sent["anchors"].([]interface{})
	if len(anchors) == 0 {
		t.Fatal("the identity was founded committing to nothing")
	}
	event := map[string]interface{}{"a": anchors}
	x, kem, err := iacrypto.AnchoredAgreementKeys(event)
	if err != nil {
		t.Fatalf("the anchor this agent writes cannot be read back: %v", err)
	}

	// What the agent publishes.
	ks, err := s.keySetFor(aid)
	if err != nil {
		t.Fatalf("no keyset was kept for the identity that was just founded: %v", err)
	}
	did, err := ks.DID()
	if err != nil {
		t.Fatal(err)
	}
	if err := did.MatchesAnchoredKeys(x, kem); err != nil {
		t.Fatalf("the published keys are not the ones the identifier commits to: %v", err)
	}
}

// And the check that consumes it agrees — end to end, through the same function
// a counterparty runs.
func TestAFoundedIdentityPassesThePeerKeyCheckAsAnchored(t *testing.T) {
	const aid = "EFoundedHere2"
	s := witnessWithSeed(t, 1)
	var sent map[string]interface{}
	s.KeriDriver = fakeInceptionDriver(t, aid, &sent)

	if w := inceptionRequest(t, s, map[string]any{
		"public_key": "Dpub", "next_public_key": "Dnext",
	}); w.Code != http.StatusCreated {
		t.Fatalf("inception failed: %d %s", w.Code, w.Body.String())
	}

	ks, _ := s.keySetFor(aid)
	did, _ := ks.DID()
	did.AID = aid

	kel := []map[string]interface{}{{"t": "icp", "s": "0", "i": aid, "a": sent["anchors"]}}
	// No signing key passed: an anchored identity must not need one. That is
	// the point of anchoring — nothing else has to be true first.
	trust, err := checkPeerKeys(did, kel, "")
	if err != nil {
		t.Fatalf("a freshly founded identity was not trusted with its own keys: %v", err)
	}
	if trust != peerKeysAnchored {
		t.Fatalf("trust was %q, want %q", trust, peerKeysAnchored)
	}
}

// Substituting the keys must fail even though the identifier is unchanged —
// otherwise the anchor is decoration.
func TestSubstitutedKeysAreRefusedAgainstAnAnchoredIdentity(t *testing.T) {
	const aid = "EFoundedHere3"
	s := witnessWithSeed(t, 1)
	var sent map[string]interface{}
	s.KeriDriver = fakeInceptionDriver(t, aid, &sent)

	if w := inceptionRequest(t, s, map[string]any{
		"public_key": "Dpub", "next_public_key": "Dnext",
	}); w.Code != http.StatusCreated {
		t.Fatalf("inception failed: %d %s", w.Code, w.Body.String())
	}

	// Somebody else's keys, offered under this identifier.
	other := witnessWithSeed(t, 9)
	other.KeriDriver = fakeInceptionDriver(t, "EImpostor", nil)
	if w := inceptionRequest(t, other, map[string]any{
		"public_key": "Dpub", "next_public_key": "Dnext",
	}); w.Code != http.StatusCreated {
		t.Fatalf("second inception failed: %d %s", w.Code, w.Body.String())
	}
	impostorKS, _ := other.keySetFor("EImpostor")
	impostorDID, _ := impostorKS.DID()
	impostorDID.AID = aid // claiming to be the first identity

	kel := []map[string]interface{}{{"t": "icp", "s": "0", "i": aid, "a": sent["anchors"]}}
	trust, err := checkPeerKeys(impostorDID, kel, "")
	if err == nil {
		t.Fatal("keys that the identifier does not commit to were accepted")
	}
	if trust == peerKeysAnchored {
		t.Fatalf("substituted keys were reported as anchored")
	}
}

// The keys must be on disk before the identity is, or an identifier can end up
// committing to a keyset nobody holds — permanently, since no later event can
// withdraw the commitment.
func TestTheMessagingKeysSurviveTheFoundingRequest(t *testing.T) {
	const aid = "EFoundedHere4"
	s := witnessWithSeed(t, 1)
	s.KeriDriver = fakeInceptionDriver(t, aid, nil)

	if w := inceptionRequest(t, s, map[string]any{
		"public_key": "Dpub", "next_public_key": "Dnext",
	}); w.Code != http.StatusCreated {
		t.Fatalf("inception failed: %d %s", w.Code, w.Body.String())
	}
	if !s.hasKeySet(aid) {
		t.Fatal("the identity committed to messaging keys that were never kept")
	}
}
