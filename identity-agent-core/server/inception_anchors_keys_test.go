package server

import (
	"net/http"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/drivers/driverfake"
	"identity-agent-core/iacrypto"
)

// An engine that hands back an inception event carrying whatever anchors it was
// given, which is what a real engine does. Enough to exercise what this agent
// sends and what it does with the result, without a KERI runtime. When seen is
// non-nil the request is captured under the same keys the wire form used, so a
// test can assert on what the agent committed to.
func fakeInceptionDriver(t *testing.T, aid string, seen *map[string]interface{}) *driverfake.Engine {
	t.Helper()
	return &driverfake.Engine{
		InceptFunc: func(req drivers.InceptionRequest) (*drivers.DriverInceptionResponse, error) {
			anchors := make([]interface{}, 0, len(req.AnchorData))
			for _, a := range req.AnchorData {
				anchors = append(anchors, a)
			}
			if seen != nil {
				*seen = map[string]interface{}{
					"public_key":      req.PublicKey,
					"next_public_key": req.NextPublicKey,
					"anchors":         anchors,
				}
			}
			event := map[string]interface{}{
				"v": "KERI10JSON", "t": "icp", "s": "0", "i": aid,
				"k": []interface{}{req.PublicKey},
			}
			if len(anchors) > 0 {
				event["a"] = anchors
			}
			return &drivers.DriverInceptionResponse{
				AID:            aid,
				InceptionEvent: event,
				PublicKey:      req.PublicKey,
				NextKeyDigest:  "Enext",
			}, nil
		},
	}
}

// The loop that had never closed: an identity founded here commits to its own
// messaging keys, and the keys it later publishes are those same keys.
//
// Before this, every identifier answered "not anchored", so the strong half of
// the peer-key check was unreachable and every agent fell back to being taken
// at its word.
func TestAFoundedIdentityCommitsToTheKeysItPublishes(t *testing.T) {
	// This is about what founding produces, not about where it is
	// allowed to happen. The machines these run on are the machines the
	// platform check refuses, so it stands in for one that may found.
	aMachineThatMayFound(t)
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
	// This is about what founding produces, not about where it is
	// allowed to happen. The machines these run on are the machines the
	// platform check refuses, so it stands in for one that may found.
	aMachineThatMayFound(t)
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
	// This is about what founding produces, not about where it is
	// allowed to happen. The machines these run on are the machines the
	// platform check refuses, so it stands in for one that may found.
	aMachineThatMayFound(t)
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
	// This is about what founding produces, not about where it is
	// allowed to happen. The machines these run on are the machines the
	// platform check refuses, so it stands in for one that may found.
	aMachineThatMayFound(t)
	const aid = "EFoundedHere4"
	s := witnessWithSeed(t, 1)
	s.KeriDriver = fakeInceptionDriver(t, aid, nil)

	if w := inceptionRequest(t, s, map[string]any{
		"public_key": "Dpub", "next_public_key": "Dnext",
	}); w.Code != http.StatusCreated {
		t.Fatalf("inception failed: %d %s", w.Code, w.Body.String())
	}
	if has, err := s.hasKeySet(aid); err != nil || !has {
		t.Fatal("the identity committed to messaging keys that were never kept")
	}
}
