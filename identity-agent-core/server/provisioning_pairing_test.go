package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/store"
)

// The one unauthenticated endpoint has to earn it. These tests are the terms.

// It must answer before an owner exists — that is the entire point. A fresh
// instance has no identity and no owner, so an owner-gated endpoint would be
// unreachable by anyone, forever.
func TestPairingIsReachableBeforeAnOwnerExists(t *testing.T) {
	if got := classify("GET", "/api/provisioning/pairing"); got != accessPublic {
		t.Fatalf("classified %q — a fresh instance would be unreachable", got)
	}
}

// Once the instance has an identity it has been paired, and an unauthenticated
// caller has no business here any more.
func TestPairingStopsAnsweringOncePaired(t *testing.T) {
	resetPairingOfferForTest()
	dir := t.TempDir()
	ds, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	if err := ds.SaveIdentity(store.IdentityState{AID: "EPAIREDALREADY", PublicKey: "DKEY"}); err != nil {
		t.Skipf("cannot save identity: %v", err)
	}
	s := &CoreServer{DataDir: dir, DataStore: ds}

	w := httptest.NewRecorder()
	s.handleProvisioningPairing(w, httptest.NewRequest(http.MethodGet, "/api/provisioning/pairing", nil))
	if w.Code != http.StatusConflict {
		t.Errorf("an already-paired instance still offered pairing: %d %s", w.Code, w.Body)
	}
}

// It discloses a pairwise AID and an OOBI, and nothing else. No root AID, no
// key, no profile, nothing about a person.
func TestPairingDisclosesNothingBeyondThePairwiseOffer(t *testing.T) {
	resetPairingOfferForTest()
	pairingOnce.Lock()
	pairingOnce.offer = &pairingOffer{AID: "EPAIRWISE", OOBI: "https://box.example/public/oobi/EPAIRWISE"}
	pairingOnce.Unlock()

	s := &CoreServer{DataDir: t.TempDir()}
	w := httptest.NewRecorder()
	s.handleProvisioningPairing(w, httptest.NewRequest(http.MethodGet, "/api/provisioning/pairing", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	// The offer carries what somebody pairing needs and nothing more: where the
	// box is, and proof they are the one who provisioned it. Anything beyond
	// this list is a disclosure by an endpoint that answers without authorisation.
	// adoption_code is NOT on this list, and its absence is the point.
	//
	// It used to be. This test exists to prove the offer discloses nothing it
	// should not, and the secret that gated adoption was sitting on its
	// allow-list -- so the test passed while the endpoint handed ownership of a
	// paid-for box to whoever asked first. A guard that blesses the thing it
	// guards against is worse than no guard, because it reads like coverage.
	allowed := map[string]bool{"aid": true, "oobi": true, "attestation": true, "attestation_binding": true}
	for field := range body {
		if !allowed[field] {
			t.Errorf("the offer discloses %q, which nothing pairing needs", field)
		}
	}
	if body["aid"] == nil || body["oobi"] == nil {
		t.Fatalf("the offer must carry an aid and an oobi, got %v", body)
	}
}

// The offer must never carry a claim token.
//
// The inverse of the test that used to be here, which asserted every offer
// carried one. That was true, and it was the defect: this response is served to
// anyone who asks, so a token inside it is a token published to the world. The
// instance is now told what to expect by whoever provisioned it, before it is
// reachable, and mints nothing itself.
func TestTheOfferNeverCarriesAClaimToken(t *testing.T) {
	offer, err := newPairingOffer("EPAIRWISE", "https://box.example/public/oobi/EPAIRWISE")
	if err != nil {
		t.Fatalf("mint offer: %v", err)
	}
	raw, err := json.Marshal(offer)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Checked on the serialised form rather than the struct, because what
	// matters is what goes over the wire -- a field added back under any name
	// would show up here.
	for _, forbidden := range []string{"adoption_code", "claim_token", "token", "secret"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("the published offer contains %q: %s", forbidden, raw)
		}
	}
}

// An instance that has not been told what to expect refuses every claim.
//
// Refusing is the safe direction. A box nobody can claim is recoverable; a box
// anybody can claim is not.
func TestAnInstanceNobodyToldRefusesEveryClaim(t *testing.T) {
	resetExpectedClaimForTest()
	if _, _, told := expectedAdoption(); told {
		t.Fatal("a fresh instance already believes it knows which claim to accept")
	}
}

// The first thing to tell it wins.
//
// The provisioner sets this during bring-up, while the box is reachable only
// from the host that started it. A caller arriving later over a public address
// must not be able to point the box at a claim of their own.
func TestOnlyTheFirstClaimExpectationIsAccepted(t *testing.T) {
	resetExpectedClaimForTest()
	if err := SetExpectedClaim("TOKEN-FROM-THE-PROVISIONER", "EBuyer"); err != nil {
		t.Fatalf("first write refused: %v", err)
	}
	if err := SetExpectedClaim("TOKEN-FROM-AN-ATTACKER", "EAttacker"); err == nil {
		t.Fatal("a second caller redirected the box to their own claim")
	}
	token, owner, told := expectedAdoption()
	if !told || token != "TOKEN-FROM-THE-PROVISIONER" || owner != "EBuyer" {
		t.Fatalf("the expectation moved: %q / %q", token, owner)
	}
}

// Half an expectation is not an expectation.
func TestAClaimExpectationNeedsBothHalves(t *testing.T) {
	for _, tc := range []struct{ token, owner string }{
		{"", "EBuyer"}, {"TOKEN", ""}, {"", ""},
	} {
		resetExpectedClaimForTest()
		if err := SetExpectedClaim(tc.token, tc.owner); err == nil {
			t.Errorf("accepted token=%q owner=%q, which cannot gate anything", tc.token, tc.owner)
		}
	}
}

// A provisioning retry must describe the same box. Minting a second AID would
// hand the user an OOBI for something other than what was reported ready.
func TestPairingMintsOnce(t *testing.T) {
	resetPairingOfferForTest()
	pairingOnce.Lock()
	pairingOnce.offer = &pairingOffer{AID: "EFIRST", OOBI: "https://box.example/public/oobi/EFIRST"}
	pairingOnce.Unlock()

	s := &CoreServer{DataDir: t.TempDir()}
	var seen []string
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		s.handleProvisioningPairing(w, httptest.NewRequest(http.MethodGet, "/api/provisioning/pairing", nil))
		var body pairingOffer
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		seen = append(seen, body.AID)
	}
	for _, aid := range seen {
		if aid != seen[0] {
			t.Fatalf("the offer changed between calls: %v", seen)
		}
	}
}

// Absence of an attestation is a real answer, not a gap. Outside a sealed VM
// the field is empty, and a caller that requires sealed infrastructure must be
// able to tell that from a report it simply did not parse.
func TestPairingOfferOmitsAttestationOutsideASealedVM(t *testing.T) {
	resetPairingOfferForTest()
	pairingOnce.Lock()
	pairingOnce.offer = &pairingOffer{AID: "EPAIRWISE", OOBI: "https://box.example/public/oobi/EPAIRWISE"}
	pairingOnce.Unlock()

	s := &CoreServer{DataDir: t.TempDir()}
	w := httptest.NewRecorder()
	s.handleProvisioningPairing(w, httptest.NewRequest(http.MethodGet, "/api/provisioning/pairing", nil))

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if _, present := body["attestation"]; present {
		t.Error("an attestation appeared on a machine that cannot produce one")
	}
}

// When a report is present it must be bound to the AID in the same response,
// or it proves something about a different instance.
func TestAttestationIsBoundToTheAdvertisedAID(t *testing.T) {
	resetPairingOfferForTest()
	pairingOnce.Lock()
	pairingOnce.offer = &pairingOffer{
		AID:                "EPAIRWISE",
		OOBI:               "https://box.example/public/oobi/EPAIRWISE",
		Attestation:        "AAAA",
		AttestationBinding: `blake3-256(IA-SNP-BIND-V1\nEPAIRWISE)`,
	}
	pairingOnce.Unlock()

	s := &CoreServer{DataDir: t.TempDir()}
	w := httptest.NewRecorder()
	s.handleProvisioningPairing(w, httptest.NewRequest(http.MethodGet, "/api/provisioning/pairing", nil))

	var offer pairingOffer
	if err := json.Unmarshal(w.Body.Bytes(), &offer); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if !strings.Contains(offer.AttestationBinding, offer.AID) {
		t.Errorf("the report is bound to %q but the offer advertises %q — it proves nothing about this instance",
			offer.AttestationBinding, offer.AID)
	}
}

// resetExpectedClaimForTest clears what an instance was told, so each test
// starts from a box nobody has spoken to.
func resetExpectedClaimForTest() {
	expectedClaim.Lock()
	defer expectedClaim.Unlock()
	expectedClaim.token, expectedClaim.ownerAID, expectedClaim.set = "", "", false
}
