package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sealOf builds an owner seal and returns it the way a reader actually sees
// one: parsed out of an event, rather than as the writer's raw JSON.
//
// Going through the real builder and a real round trip is deliberate. A test
// that hand-wrote the map would keep passing if the writer changed shape, which
// is exactly the failure — ownership unreadable — that these tests exist to
// catch.
func sealOf(t *testing.T, ownerAID string) map[string]interface{} {
	t.Helper()
	raw, err := ownerAnchorSeal(ownerAID)
	if err != nil {
		t.Fatalf("building an owner seal for %s: %v", ownerAID, err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("the owner seal is not readable JSON: %v", err)
	}
	return parsed
}

func inception(seals ...map[string]interface{}) []map[string]interface{} {
	event := map[string]interface{}{"t": "icp", "s": "0", "i": "EOrg"}
	if len(seals) > 0 {
		raw := make([]interface{}, 0, len(seals))
		for _, s := range seals {
			raw = append(raw, s)
		}
		event["a"] = raw
	}
	return []map[string]interface{}{event}
}

// The ordinary case: an identity names its owner where anybody can read it.
func TestTheOwnerIsReadFromTheInception(t *testing.T) {
	owner, err := ownerFromKEL(inception(sealOf(t, "EFounder")))
	if err != nil {
		t.Fatal(err)
	}
	if owner != "EFounder" {
		t.Errorf("owner read as %q, want EFounder", owner)
	}
}

// A person's own agent is a delegated identity — its delegator is already named
// in the event, so it carries no separate owner seal. Requiring one would break
// every individual agent.
func TestAnIdentityWithNoOwnerSealIsNotAnError(t *testing.T) {
	owner, err := ownerFromKEL(inception())
	if err != nil {
		t.Fatalf("an identity with no owner seal was treated as broken: %v", err)
	}
	if owner != "" {
		t.Errorf("invented an owner: %q", owner)
	}
}

// Only the inception is consulted. A later event must not be able to introduce
// an owner where there was none — that would reintroduce the silent overwrite
// the anchor exists to remove.
func TestALaterEventCannotIntroduceAnOwner(t *testing.T) {
	kel := inception()
	kel = append(kel, map[string]interface{}{
		"t": "ixn", "s": "1", "i": "EOrg",
		"a": []interface{}{sealOf(t, "EOpportunist")},
	})

	owner, err := ownerFromKEL(kel)
	if err != nil {
		t.Fatal(err)
	}
	if owner != "" {
		t.Errorf("a later event claimed ownership of an unowned identity: %q", owner)
	}
}

// Nor may a later event replace one. Changing owners is a rotation ceremony
// with its own rules, not a seal somebody appends.
func TestALaterEventCannotReplaceTheOwner(t *testing.T) {
	kel := inception(sealOf(t, "EFounder"))
	kel = append(kel, map[string]interface{}{
		"t": "ixn", "s": "1", "i": "EOrg",
		"a": []interface{}{sealOf(t, "EUsurper")},
	})

	owner, err := ownerFromKEL(kel)
	if err != nil {
		t.Fatal(err)
	}
	if owner != "EFounder" {
		t.Errorf("the founder was displaced by a later event: %q", owner)
	}
}

// A seal claiming the owner role and naming nobody is malformed. Skipping it
// would make a broken identity look like an unowned one, and those need
// different answers.
func TestAnOwnerSealNamingNobodyIsAnError(t *testing.T) {
	_, err := ownerFromKEL(inception(map[string]interface{}{"i": "", "s": "0", "d": ""}))
	if err == nil {
		t.Fatal("a malformed owner seal passed as no owner at all")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Errorf("the error should distinguish a broken record from an absent one, got: %v", err)
	}
}

// Other seals are none of this function's business.
func TestUnrelatedSealsAreIgnored(t *testing.T) {
	owner, err := ownerFromKEL(inception(
		map[string]interface{}{"i": "ESomething", "r": "something-else"},
		sealOf(t, "EFounder"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if owner != "EFounder" {
		t.Errorf("owner read as %q among unrelated seals", owner)
	}
}

func TestAnEmptyLogHasNoOwnerToRead(t *testing.T) {
	if _, err := ownerFromKEL(nil); err == nil {
		t.Error("an empty log answered a question it cannot answer")
	}
}

// The first event has to actually be an inception, or the identity is not what
// it claims and nothing after it can be trusted either.
func TestALogNotStartingWithAnInceptionIsRefused(t *testing.T) {
	_, err := ownerFromKEL([]map[string]interface{}{
		{"t": "ixn", "s": "0", "i": "EOrg"},
	})
	if err == nil {
		t.Error("a log beginning with an interaction event was accepted")
	}
}

// Written in one place, read in one place. If these disagree, ownership becomes
// unreadable in a way no single test would catch.
func TestTheSealShapeRoundTrips(t *testing.T) {
	seal := sealOf(t, "EFounder")
	owner, err := ownerFromKEL(inception(seal))
	if err != nil || owner != "EFounder" {
		t.Fatalf("the seal this code writes is not the seal it reads: %v %q", err, owner)
	}

	// The shape is a KERI event seal and nothing else. An extra field, or a
	// different set, is refused by strict readers — which is how the previous
	// shape made owned identities unreadable — so it is pinned here rather than
	// left to be noticed by another implementation later.
	if len(seal) != 3 {
		t.Fatalf("an owner seal has %d fields; a KERI event seal has exactly 3: %v",
			len(seal), seal)
	}
	if seal["i"] != "EFounder" || seal["s"] != "0" || seal["d"] != "EFounder" {
		t.Errorf("the seal does not name the owner's inception: %v", seal)
	}

	// The written form must be in the specified field order, which a Go map
	// cannot express. Sorted order is refused by other implementations.
	raw, err := ownerAnchorSeal("EFounder")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); got != `{"i":"EFounder","s":"0","d":"EFounder"}` {
		t.Errorf("the seal is written as %s, which is not the specified field order", got)
	}
}

// An owner has to be an identity whose inception digest IS its identifier, or
// the seal names an event that does not exist.
func TestAnOwnerThatCannotBeSealedIsRefused(t *testing.T) {
	if _, err := ownerAnchorSeal("DBasicPrefixNotSelfAddressing"); err == nil {
		t.Error("an owner seal was built pointing at no event")
	}
	if _, err := ownerAnchorSeal(""); err == nil {
		t.Error("an owner seal was built naming nobody")
	}
}

// Founding an identity as its own root requires naming its owner.
//
// Such an identity answers to somebody other than itself, and nothing else in
// the event says who. If this could be skipped, the very failure the anchor
// exists to prevent — an identity that
// answers to itself — would be reachable again through the front door.
func TestFoundingARootIdentityWithoutAnOwnerIsRefused(t *testing.T) {
	s := witnessWithStore(t)
	s.KeriDriver = nil // never reached: the owner check comes first

	body, _ := json.Marshal(map[string]interface{}{
		"found_as_root": true,
		"adoption_code": "irrelevant",
	})
	r := httptest.NewRequest(http.MethodPost, "/api/pairing/adopt", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handlePairingComplete(w, r)

	// Any refusal will do; what matters is that it does not proceed to found an
	// identity with nobody answering for it.
	if w.Code == http.StatusOK {
		t.Fatal("an identity was founded as its own root with no owner")
	}
}
